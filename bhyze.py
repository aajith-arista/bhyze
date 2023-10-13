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
from tabulate import tabulate
from typing import Optional

def parseArgs():
   parser = argparse.ArgumentParser()
   sub_parsers = parser.add_subparsers( dest='subcommand',
                                        help='sub commands' )
   diff_parser = sub_parsers.add_parser( 'diff',
                                         help='Diff two builds' )
   diff_parser.add_argument( 'reference_id',
                             type=int,
                             help='Reference build-id' )
   diff_parser.add_argument( 'inspect_id',
                             type=int,
                             help='Inspect build-id' )
   diff_sub_parsers =  diff_parser.add_subparsers( dest='diff_subcommand',
                                                   help='diff subcommands' )

   summary_parser = diff_sub_parsers.add_parser( 'summary',
                                                 help='Display summary of diff' )
   summary_parser.add_argument( '--pkg-limit', '-l',
                                type=int, default=None,
                                help='Limit computation to first '
                                     '<PKG_LIMIT> packages' )
   summary_parser.add_argument( '--display-start', '-ds',
                                type=int, default=None,
                                help='Start displaying from <DISPLAY_START>th '
                                     'package' )
   summary_parser.add_argument( '--display-limit', '-dl',
                                type=int, default=None,
                                help='Limit displaying differences for '
                                '<DISPLAY_LIMIT> packages' )

   package_parser = diff_sub_parsers.add_parser(
         'package',
         help='Display details of a package' )
   package_parser.add_argument( 'pkg',
                                type=str,
                                help='Specify package' )


   args = parser.parse_args()
   return args

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

def checkPath( client: SshClient, path: str, isFile: bool ):
   flag = '-f' if isFile else '-d'
   cmd = f'test {flag} {path}'
   client.runCmd( cmd )

@dataclass
class AbuildInfo():
   start: str
   submit: str
   publish: str
   buildId: str
   project: str
   platform: str
   bs: str

   def workspacePath( self ) -> str:
      return f'/var/Abuild/{self.project}/{self.start}'

   def buildhashLogBasePath( self ) -> str:
      return os.path.join( self.workspacePath(), 'tmp/buildhash' )

   def abuildLogPath( self ) -> str:
      return os.path.join( self.workspacePath(), 'Abuild.log' )

   def validate( self, client: SshClient, pkg: Optional[str] = None ) -> str:
      if pkg is not None:
         path = os.path.join( self.buildhashLogBasePath(), f'{pkg}.log' )
         isFile = True
      else:
         path = self.buildhashLogBasePath()
         isFile=False
      checkPath( client, path, isFile )

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

buildhashPattern = re.compile( r'buildhash now (\S*)' )

CACHE_DIR = "/var/cache/bhyze"

def pickleFilepath( bi: AbuildInfo, limit ) -> str:
   filename = f'id-{bi.buildId}_limit-{limit}.pkl'
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

   def populateHashLogsSet( self, client: SshClient ) -> None:
      cmd = f'ls {self.bi.buildhashLogBasePath()}'
      cmdOutput, _ = client.runCmd( cmd )
      cmdOutputLines = cmdOutput.splitlines()
      self.hashLogs = { x.split( '.' )[ 0 ] for x in cmdOutputLines }

   def populatePkgBuildOrder( self, client: SshClient ) -> None:
      cmd = ' '.join( [
         'grep', '-m', '1',
         '''"'a4 make' packages:"''',
         self.bi.abuildLogPath() ] )
      cmdOutput, _ = client.runCmd( cmd )
      pattern = r"'a4 make' packages:\s*(.*)"
      mObj = re.search( pattern, cmdOutput )
      pkgList = mObj.group( 1 ).split()
      self.pkgDepOrder = [ p.removesuffix( '(!)' ) for p in pkgList ]

   def pkgHashLog( self, pkg: str ) -> str:
      return os.path.join( self.bi.buildhashLogBasePath(), pkg + '.log' )

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

def diffSummaryCmd( args ):
   rbi = getAbuildInfo( args.reference_id )
   ibi = getAbuildInfo( args.inspect_id )

   assert rbi.platform == ibi.platform

   pkgLimit = args.pkg_limit
   with SshClient( rbi.bs ) as refClient, SshClient( ibi.bs ) as insClient:
      rhi = LoadHashInfo( rbi, pkgLimit )
      ihi = LoadHashInfo( ibi, pkgLimit )

      for client, hi in zip( [ refClient, insClient ], [ rhi, ihi ] ):
         hi.bi.validate( client )
         if not hi.populated:
            hi.populateAll( client, pkgLimit )

   iterLimit = pkgLimit or len( ihi.pkgDepOrder )
   displayList = []
   reasonVerbose = {
      'content': 'package contents changed',
      'deps': 'depSig changed',
      'final': 'build setting/env changed',
   }
   matchCount = 0
   accounted = 0
   for pkg in ihi.pkgDepOrder[ : iterLimit ]:
      if pkg not in ihi.buildhash:
         continue
      if pkg not in rhi.buildhash:
         continue
      accounted += 1
      ibh = ihi.buildhash[ pkg ]
      rbh = rhi.buildhash[ pkg ]

      if ibh[ 'final' ] == rbh[ 'final' ]:
         matchCount += 1
         continue

      if ibh[ 'content' ] != rbh[ 'content' ]:
         displayList.append( ( pkg, reasonVerbose[ 'content' ] ) )
      elif ibh[ 'deps' ] != rbh[ 'deps' ]:
         displayList.append( ( pkg, reasonVerbose[ 'deps' ] ) )
      else:
         displayList.append( ( pkg, reasonVerbose[ 'final' ] ) )
         displayList[ pkg ] = 'final'

   print( f'Total packages considered: {iterLimit}' )
   print( f'Hashes encountered: {accounted}' )
   print( f'Num of matching hashes: {accounted - len( displayList )}' )
   print( f'Num of mismatched hashes: {len( displayList )}' )
   print( '' )

   displayStart = 0 if args.display_start is None else args.display_start
   displayLimit = args.display_limit or len( displayList )
   displayEnd = displayStart + displayLimit
   print( tabulate( displayList[ displayStart : displayEnd ],
                    headers=[ 'pkg', 'reason' ] ) )

class PackageDif:
   def __init__( self, rbi: AbuildInfo, ibi: AbuildInfo, pkg: str ):
      self.rbi = rbi
      self.ibi = ibi

      self.rlog = None
      self.ilog = None
      self.rdeplog = None
      self.ideplog = None

def diffPackageCmd( args ):
   rbi = getAbuildInfo( args.reference_id )
   ibi = getAbuildInfo( args.inspect_id )

   assert rbi.platform == ibi.platform
   pkg = args.pkg

   with SshClient( rbi.bs ) as refClient, SshClient( ibi.bs ) as insClient:
      rhi = HashInfo( rbi )
      ihi = HashInfo( ibi )

      for client, hi in zip( [ refClient, insClient ], [ rhi, ihi ] ):
         hi.bi.validate( client, pkg )
         #hi.loadLogs()
      import pdb
      pdb.set_trace()
      print( "hello" )

def main():
   args = parseArgs()
   if args.subcommand == 'diff':
      if args.diff_subcommand == 'summary':
         diffSummaryCmd( args )
      elif args.diff_subcommand == 'package':
         diffPackageCmd( args )
      else:
         assert False, f'Unknown diff subcommand {args.diff_subcommand}'
   else:
      assert False, f'Unknown subcommand {args.subcommand}'

if __name__ == "__main__":
   main()
