#!/usr/bin/python3
# Copyright (c) 2023 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

import argparse
from collections import defaultdict
from dataclasses import dataclass, field
import os
import paramiko
# import pdb
import pickle
import re
import subprocess
import sys

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

@dataclass
class AbuildInfo():
   start: str
   submit: str
   publish: str
   buildId: str
   project: str
   platform: str
   bs: str

def getAbuildInfo( buildId: int ) -> AbuildInfo:
   cmd = [ "ap", "abuild", "-q", "-i", str( buildId ) ]
   apAbuildOutput = subprocess.check_output( cmd, text=True,
                                             encoding="utf-8" )
   lines = apAbuildOutput.splitlines()
   dataFields = lines[ 2 ].split()

   dataFields = dataFields[ : 7 ]
   abuildInfo = AbuildInfo( *dataFields )
   assert abuildInfo.buildId == str( buildId )
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

CACHE_DIR = "/var/cache/bhyze"

def pickleFilepath( bi: AbuildInfo, limit ) -> str:
   filename =  f'id-{bi.buildId}_limit-{limit}.pkl'
   return os.path.join( CACHE_DIR, filename )

def innerDict():
   return defaultdict( str )

def outerDict():
   return defaultdict( innerDict )

@dataclass
class HashInfo():
   bi: AbuildInfo
   hashLogs: set = field( default_factory=set )
   pkgDepOrder: list = field( default_factory=list )

   # Avoid lambda to support pickling
   buildhash: defaultdict = field( default_factory=outerDict )

   populated: bool = False

   def workspacePath( self ) -> str:
      return f'/var/Abuild/{self.bi.project}/{self.bi.start}'

   def buildhashLogBasePath( self ) -> str:
      return os.path.join( self.workspacePath(), 'tmp/buildhash' )

   def abuildLogPath( self ) -> str:
      return os.path.join( self.workspacePath(), 'Abuild.log' )

   def validate( self, client: SshClient ) -> str:
      cmd = f'test -d {self.buildhashLogBasePath()}'
      client.runCmd( cmd )

   def populateHashLogsSet( self, client: SshClient ) -> None:
      cmd = f'ls {self.buildhashLogBasePath()}'
      cmdOutput, _ = client.runCmd( cmd )
      cmdOutputLines = cmdOutput.splitlines()
      self.hashLogs = { x.split( '.' )[ 0 ] for x in cmdOutputLines }

   def populatePkgBuildOrder( self, client: SshClient ) -> None:
      cmd = ' '.join( [
         'grep', '-m', '1',
         '''"'a4 make' packages:"''',
         self.abuildLogPath() ] )
      cmdOutput, _ = client.runCmd( cmd )
      pattern = r"'a4 make' packages:\s*(.*)"
      mObj = re.search( pattern, cmdOutput )
      pkgList = mObj.group( 1 ).split()
      self.pkgDepOrder = [ p.removesuffix( '(!)' ) for p in pkgList ]

   def pkgHashLog( self, pkg: str ) -> str:
      return os.path.join( self.buildhashLogBasePath(), pkg + '.log' )

   def populateBuildHashForPkg( self, client: SshClient, pkg: str ) -> None:
      if pkg not in self.hashLogs:
         return

      def populateHashType( htype, cmd ):
         cmdOutput, _ = client.runCmd( cmd )
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

   def populateBuildhashes( self, client: SshClient, pkgLimit: int ) -> None:
      if pkgLimit is None:
         pkgLimit = len( self.pkgDepOrder )
      for pkg in self.pkgDepOrder[ : pkgLimit ]:
         self.populateBuildHashForPkg( client, pkg )

   def pickle( self, pkgLimit: int ) -> None:
      with open( pickleFilepath( self.bi, pkgLimit ), 'wb' ) as f:
         pickle.dump( self, f )

   def populateAll( self, client: SshClient, pkgLimit: int ) -> None:
      self.populateHashLogsSet( client )
      self.populatePkgBuildOrder( client )
      self.populateBuildhashes( client, pkgLimit )
      self.populated = True
      self.pickle( pkgLimit )

def LoadHashInfo( bi: AbuildInfo, pkgLimit: int ) -> HashInfo:
   fpath = pickleFilepath( bi, pkgLimit )
   if os.path.exists( fpath ):
      with open( fpath, 'rb' ) as f:
         hi = pickle.load( f )
      assert isinstance( hi, HashInfo )
      assert hi.bi == bi
   else:
      hi = HashInfo( bi )
   return hi

def main():
   args = parseArgs()
   rbi = getAbuildInfo( args.reference_id )
   ibi = getAbuildInfo( args.inspect_id )

   assert rbi.platform == ibi.platform

   pkgLimit = args.pkg_limit
   with SshClient( rbi.bs ) as refClient, SshClient( ibi.bs ) as insClient:
      rhi = LoadHashInfo( rbi, pkgLimit )
      ihi = LoadHashInfo( ibi, pkgLimit )

      for client, hi in zip( [ refClient, insClient ], [ rhi, ihi ] ):
         hi.validate( client )
         if not hi.populated:
            hi.populateAll( client, pkgLimit )

if __name__ == "__main__":
   main()
