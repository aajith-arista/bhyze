#!/usr/bin/python3
# Copyright (c) 2023 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

import argparse
from collections import namedtuple, defaultdict
import os
import paramiko
# import pdb
import re
import subprocess
import sys

buildInfoFields = [ 'start', 'submit', 'publish', 'id', 'project',
                    'platform', 'bs' ]
AbuildInfo = namedtuple( "AbuildInfo", buildInfoFields )

def parseArgs():
   parser = argparse.ArgumentParser()
   parser.add_argument( '--reference-id', '-r',
                        type=int,
                        required=True,
                        help='Reference build-id' )
   parser.add_argument( '--inspect-id', '-i',
                        type=int,
                        required=True,
                        help='Inspect build-id' )
   parser.add_argument( '--pkg-limit', '-l',
                        type=int, default=None,
                        help='Limit computation to first <PKG_LIMIT> packages' )

   args = parser.parse_args()
   return args

def getAbuildInfo( buildId: int ) -> AbuildInfo:
   cmd = [ "ap", "abuild", "-q", "-i", str( buildId ) ]
   apAbuildOutput = subprocess.check_output( cmd, text=True,
                                             encoding="utf-8" )
   lines = apAbuildOutput.splitlines()
   dataFiledHeaders = lines[ 0 ].split()[ : len( buildInfoFields ) ]
   dataFields = lines[ 2 ].split()

   assert dataFiledHeaders == buildInfoFields
   dataFields = dataFields[ : len( buildInfoFields ) ]
   abuildInfo = AbuildInfo( *dataFields )
   assert abuildInfo.id == str( buildId )
   return abuildInfo

class SshClient( paramiko.SSHClient ):
   def __init__( self, host ):
      super().__init__()
      self.host = host
      self.set_missing_host_key_policy( paramiko.AutoAddPolicy() )
      self.username = 'arastra'
      self.keyFile = f'/home/{self.username}/.ssh/id_rsa'
      self.connected = False

   def __enter__( self ):
      self.close()
      self.connected = False
      self.connect( self.host,
                    username=self.username,
                    key_filename=self.keyFile )
      self.connected = True
      return self

   def __exit__( self, etype, value, traceback ):
      self.close()
      self.connected = False

   class RunCmdErr( Exception ):
      def __init__( self, cmd, stdout, stderr, msg ):
         self.cmd = cmd
         self.stdout = stdout
         self.stderr = stderr
         super().__init__( msg )

   def runCmd( self, cmd: str ) -> ( str, str ):
      assert self.connected
      _, stdout, stderr = self.exec_command( cmd )
      exitCode = stdout.channel.recv_exit_status()
      stdoutText = stdout.read().decode( 'utf-8' )
      stderrText = stderr.read().decode( 'utf-8' )
      if exitCode != 0:
         errMsg = ( f'Command "{cmd}" failed '
                    f'stdout: "{stdoutText}" stderr: "{stderrText}"' )
         print( errMsg, file=sys.stderr )
         raise self.RunCmdErr( cmd, stdoutText, stderrText,
                               errMsg )
      return stdoutText, stderrText

buildhashPattern = re.compile( r'buildhash now (\S*)' )

class HashInfo:
   def __init__( self, client: SshClient, bi: AbuildInfo, pkgLimit: int ):
      self.client = client
      self.bi = bi
      self.pkgLimit = pkgLimit
      self.workspacePath = f'/var/Abuild/{self.bi.project}/{self.bi.start}'
      self.buildhashLogBasePath = os.path.join( self.workspacePath,
                                                'tmp/buildhash' )
      self.abuildLogPath = os.path.join( self.workspacePath,
                                         'Abuild.log' )
      self.hashLogs = set()
      self.pkgDepOrder = []

      self.missingHashLogs = set()

      # two-level dict
      # first level keyed by pkgName
      # second level keyed by "contents", "deps" and "final"
      self.buildhash = defaultdict( lambda: defaultdict( str ) )

   def validate( self ):
      cmd = f'test -d {self.buildhashLogBasePath}'
      self.client.runCmd( cmd )

   def populateHashLogsSet( self ) -> None:
      cmd = f'ls {self.buildhashLogBasePath}'
      cmdOutput, _ = self.client.runCmd( cmd )
      cmdOutputLines = cmdOutput.splitlines()
      self.hashLogs = { x.split( '.' )[ 0 ] for x in cmdOutputLines }

   def populatePkgBuildOrder( self ) -> None:
      cmd = ' '.join( [
         'grep', '-m', '1',
         '''"'a4 make' packages:"''',
         self.abuildLogPath ] )
      cmdOutput, _ = self.client.runCmd( cmd )
      pattern = r"'a4 make' packages:\s*(.*)"
      mObj = re.search( pattern, cmdOutput )
      pkgList = mObj.group( 1 ).split()
      self.pkgDepOrder = [ p.removesuffix( '(!)' ) for p in pkgList ]
      if self.pkgLimit is None:
         self.pkgLimit = len( self.pkgDepOrder )

      self.missingHashLogs = set( self.pkgDepOrder ) - self.hashLogs

   def pkgHashLog( self, pkg: str ) -> str:
      return os.path.join( self.buildhashLogBasePath, pkg + '.log' )

   def populateBuildHashForPkg( self, pkg: str ) -> None:
      if pkg not in self.hashLogs:
         return

      def populateHashType( htype, cmd ):
         cmdOutput, _ = self.client.runCmd( cmd )
         mObj = buildhashPattern.match( cmdOutput )
         assert mObj
         self.buildhash[ pkg ][ htype ] = mObj.group( 1 )

      buildhashTypes = [
            ( 'content',
              f'tac {self.pkgHashLog( pkg )} | grep -m 1 "due to contents of"' ),
            ( 'deps',
              f'tac {self.pkgHashLog( pkg )} | grep -m 1 "due to depSig"' ),
            ( 'final',
              f'tac {self.pkgHashLog( pkg )} | grep -m 1 "^buildhash now"' ),
         ]
      for it in buildhashTypes:
         populateHashType( *it )

   def populateBuildhashes( self ):
      for pkg in self.pkgDepOrder[ : self.pkgLimit ]:
         self.populateBuildHashForPkg( pkg )

def main():
   args = parseArgs()
   refInfo = getAbuildInfo( args.reference_id )
   insInfo = getAbuildInfo( args.inspect_id )

   assert refInfo.platform == insInfo.platform

   with SshClient( refInfo.bs ) as refClient, SshClient( insInfo.bs ) as insClient:
      rhi = HashInfo( refClient, refInfo, args.pkg_limit )
      ihi = HashInfo( insClient, insInfo, args.pkg_limit )

      for hi in [ rhi, ihi ]:
         hi.validate()
         hi.populateHashLogsSet()
         hi.populatePkgBuildOrder()
         hi.populateBuildhashes()

if __name__ == "__main__":
   main()
