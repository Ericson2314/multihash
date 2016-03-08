{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}

module Main where

import           Crypto.Hash              (Digest)
import qualified Crypto.Hash              as CH
import           Data.Byteable            (toBytes)
import           Data.ByteString          (ByteString)
import           Data.ByteString.Lazy     (toStrict)
import           Options.Applicative

import           System.IO.Streams        (InputStream, stdin, stdout,
                                           withFileAsInput, write)
import           System.IO.Streams.Crypto (hashInputStream)

import qualified Data.Multihash.Base      as MB
import qualified Data.Multihash.Digest    as MH


data SomeAlgo = forall h. MH.MultihashAlgorithm h => SomeAlgo h

instance Show SomeAlgo where
  show (SomeAlgo h) = show h

data Termination = Null | Newline deriving (Show, Eq)
data Config =
    Config
    { cfFile :: Maybe FilePath
    , cfAlgo :: SomeAlgo
    , cfBase :: MB.BaseEncoding
    , cfDigest :: Maybe String
    , cfTerm :: Termination
    } deriving Show


main :: IO ()
main = do
    -- TODO add file checking
    config <- execParser opts
    digest <- maybe (hashStdin config) (hashFile config) $ cfFile config
    write (multihash config digest) stdout
  where
    hashStdin config = hash (cfAlgo config) stdin
    hashFile config file = withFileAsInput file . hash $ cfAlgo config
    multihash (Config _file algo base _hash term) (MH.Digest d) =
      Just $ toStrict $ line term $ MB.encode base $ MH.encode d

    line Null    = (<> "\0")
    line Newline = (<> "\n")


-- TODO add BLAKE support
hash :: SomeAlgo -> InputStream ByteString -> IO MH.Digest
hash (SomeAlgo algo) is = MH.Digest <$> f algo
  where
    f :: MH.MultihashAlgorithm h => h -> IO (Digest h)
    f _ = hashInputStream is

opts :: ParserInfo Config
opts = info
       (helper <*> (Config
                    <$> fileArg
                    <*> algoOpt
                    <*> baseOpt
                    <*> checkOpt
                    <*> nullTermFlag
                   ))
       (fullDesc
        <> header "Generate a multihash for the given input."
        <> progDesc "Hash from FILE or stdin if not given.")


algoOpt :: Parser SomeAlgo
algoOpt =
    option auto
    $  long "algorithm"
    <> short 'a'
    <> metavar "ALGO"
    <> showDefault <> value (SomeAlgo CH.SHA256)
    <> help ("Hash algorithm to apply to input, ignored if checking hash " <> show
             [ SomeAlgo $ CH.SHA256
             ])


baseOpt :: Parser MB.BaseEncoding
baseOpt =
    option auto
    $  long "encoding"
    <> short 'e'
    <> metavar "ENCODING"
    <> showDefault <> value MB.Base58
    <> help ("Base encoding of output digest, ignored if checking hash " <> show ([minBound..] :: [MB.BaseEncoding]))


checkOpt :: Parser (Maybe String)
checkOpt =
    optional . option auto
    $  long "check"
    <> short 'c'
    <> metavar "DIGEST"
    <> help "Check for matching digest"


nullTermFlag :: Parser Termination
nullTermFlag =
    flag Newline Null
    $  long "print0"
    <> short '0'
    <> help "End filenames with NUL, for use with xargs"


fileArg :: Parser (Maybe FilePath)
fileArg = optional . argument str $ metavar "FILE"
