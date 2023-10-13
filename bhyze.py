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
   diff_sub_parsers = diff_parser.add_subparsers( dest='diff_subcommand',
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

   def pkgHashLog( self, pkg: str ) -> str:
      return os.path.join( self.buildhashLogBasePath(), pkg + '.log' )

   def pkgHashDepsLog( self, pkg: str ) -> str:
      return os.path.join( self.buildhashLogBasePath(), pkg + '.deps.log' )

   def validate( self, client: SshClient, pkg: Optional[ str ] = None ) -> str:
      if pkg is not None:
         path = os.path.join( self.buildhashLogBasePath(), f'{pkg}.log' )
         isFile = True
      else:
         path = self.buildhashLogBasePath()
         isFile = False
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

   def populateBuildHashForPkg( self, client: SshClient, pkg: str ) -> None:
      if pkg not in self.hashLogs:
         return

      def populateHashType( htype, cmd ):
         try:
            cmdOutput, _ = client.runCmd( cmd )
         except SshClient.RunCmdErr:
            if htype != "deps":
               raise
            self.buildhash[ pkg ][ htype ] = 'NA'
            return
         mObj = buildhashPattern.match( cmdOutput )
         assert mObj
         self.buildhash[ pkg ][ htype ] = mObj.group( 1 )

      buildhashTypes = [
            ( 'content',
              f'tac {self.bi.pkgHashLog( pkg )} | grep -m 1 "due to contents of"' ),
            ( 'deps',
              f'tac {self.bi.pkgHashLog( pkg )} | grep -m 1 "due to depSig"' ),
            ( 'final',
              f'tac {self.bi.pkgHashLog( pkg )} | grep -m 1 "^buildhash now"' ),
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

def loadFileContents( client: SshClient, path: str,
                      tolerateFailure: bool = False ) -> Optional[ str ]:
   if tolerateFailure:
      try:
         checkPath( client, path, isFile=True )
      except SshClient.RunCmdErr:
         return None

   sftpClient = client.open_sftp()
   with sftpClient.open( path ) as f:
      contents = f.read()
   return contents.decode( 'utf-8' )

def findDiffLine( l1: str, l2: str ) -> ( Optional[ str ], Optional[ str ] ):
   l1Lines = l1.splitlines()
   l2Lines = l2.splitlines()

   iterLimit = min( len( l1Lines ), len( l2Lines ) )
   for i in range( iterLimit ):
      if l1Lines[ i ] != l2Lines[ i ]:
         return ( l1Lines[ i ], l2Lines[ i ] )
   return ( None, None )

def getInstallSig( logLine ) -> str:
   depSigPattern = r"depSig now \S* due to full: len=\d*=b'(.*)'$"
   mObj = re.match( depSigPattern, logLine )
   if not mObj:
      print( f'bad log line, installSig match fail.\nline=\n{logLine}' )
      assert False, 'bad log line'
   return bytes( mObj.group( 1 ), 'utf-8' ).decode( 'unicode_escape' )

def getRpmFromInstallSig( sig ) -> str:
   return sig.splitlines()[ 0 ]

class PackageDiff:
   def __init__( self,
                 rbi: AbuildInfo,
                 rclient: SshClient,
                 ibi: AbuildInfo,
                 iclient: SshClient,
                 pkg: str ):
      self.rbi = rbi
      self.rclient = rclient
      self.ibi = ibi
      self.iclient = iclient
      self.pkg = pkg

      self.rlog = None
      self.ilog = None
      self.rdeplog = None
      self.ideplog = None

   def loadLogs( self ):
      rlogpath = self.rbi.pkgHashLog( self.pkg )
      rdeplogpath = self.rbi.pkgHashDepsLog( self.pkg )
      ilogpath = self.ibi.pkgHashLog( self.pkg )
      ideplogpath = self.ibi.pkgHashDepsLog( self.pkg )

      self.rlog = loadFileContents( self.rclient, rlogpath )
      self.rdeplog = loadFileContents( self.rclient, rdeplogpath,
                                         tolerateFailure=True )
      self.ilog = loadFileContents( self.iclient, ilogpath )
      self.ideplog = loadFileContents( self.iclient, ideplogpath,
                                       tolerateFailure=True )

   def getDepsContentSigPattern( self, rpm ):
      rpmNameWithEpoch = rpm.split( ':' )[ 0 ]
      rpmName = rpmNameWithEpoch.removesuffix( '-None' )
      rpmVersion = rpm.split( ':' )[ 1 ].split( '-' )[ 0 ]
      rpmNameWithVersion = rpmName + '-' + rpmVersion

      patternPrefix = 'CALCULATING DEPSCONTENTSIG FOR'
      patternSuffix = 'in the context of PACKAGE'
      pattern = ' '.join( [
         patternPrefix,
         rpmNameWithVersion,
         patternSuffix,
         self.pkg ] )
      return pattern

   def getDepsSubLog( self, log, pattern ):
      assert log is not None
      logLines = log.splitlines()
      startIndex = logLines.index( pattern ) + 1
      i = startIndex + 1
      endIndex = startIndex
      while i < len( logLines ):
         if logLines[ i ].startswith( 'depsContentSig now' ):
            endIndex = i
            i += 1
         else:
            break
      return '\n'.join( logLines[ startIndex : endIndex ] )

   def analyzeDepsContentSig( self, refRpm, insRpm ):
      refPattern = self.getDepsContentSigPattern( refRpm )
      refDepsLog = self.getDepsSubLog( self.rdeplog, refPattern )

      insPattern = self.getDepsContentSigPattern( insRpm )
      insDepsLog = self.getDepsSubLog( self.ideplog, insPattern )
      lhs, rhs = findDiffLine( refDepsLog, insDepsLog )
      print( 'DepsContentSig change isolated:' )
      print( f'Reference:\n\t{lhs}' )
      print( f'Inspect:\n\t{rhs}' )

   def analyzeInstallSigDiff( self, rsig, isig ):

      refRpm = getRpmFromInstallSig( rsig )
      insRpm = getRpmFromInstallSig( isig )
      if refRpm != insRpm:
         print( 'Rpm added/deleted' )
         print( f'Reference:\n\t{refRpm}' )
         print( f'Inspect:\n\t{insRpm}' )
      else:
         print( f'InstallSig of rpm {refRpm} has changed.' )
         lhs, rhs = findDiffLine( rsig, isig )
         depContentSigPrefix = 'depsContentSig:'
         if lhs.startswith( depContentSigPrefix ) and \
               rhs.startswith( depContentSigPrefix ):
            print( 'InstallSig difference is due to depContentSig change' )
            print( f'Analyzing depsContentSig computation of {refRpm} further!' )
            self.analyzeDepsContentSig( refRpm, insRpm )
         else:
            print( f'InstallSig difference is due to content change in {refRpm}' )
            print( f'Reference:\n\t{lhs}' )
            print( f'Inspect:\n\t{rhs}' )

   def analyze( self ):
      lhs, rhs = findDiffLine( self.rlog, self.ilog )
      if lhs is None:
         print( "Build hashes are the same, nothing to analyze!" )
         return
      assert rhs is not None

      buildhashChangeStr = "buildhash now"

      if lhs.startswith( buildhashChangeStr ) and \
            rhs.startswith( buildhashChangeStr ):
         print( 'Buildhash change due to contents/env/setting:' )
         print( f'Reference:\n\t{lhs}' )
         print( f'Inspect:\n\t{rhs}' )
      else:
         print( 'Buildhash change due to Depsig change' )
         refInstallSig = getInstallSig( lhs )
         insInstallSig = getInstallSig( rhs )
         self.analyzeInstallSigDiff( refInstallSig, insInstallSig )

def diffPackageCmd( args ):
   rbi = getAbuildInfo( args.reference_id )
   ibi = getAbuildInfo( args.inspect_id )

   assert rbi.platform == ibi.platform
   pkg = args.pkg

   with SshClient( rbi.bs ) as refClient, SshClient( ibi.bs ) as insClient:
      rbi.validate( refClient, pkg )
      ibi.validate( insClient, pkg )
      pd = PackageDiff( rbi, refClient,
                        ibi, insClient,
                        pkg )
      print( 'loading logs!' )
      pd.loadLogs()
      print( 'logs loaded, analyzing!' )
      pd.analyze()

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
