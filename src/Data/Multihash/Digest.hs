{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ExistentialQuantification #-}

module Data.Multihash.Digest where

import           Prelude                    hiding (length)

import           Control.Applicative        ((<$>))
import qualified Crypto.Hash                as CH
import           Crypto.Hash                hiding (Digest)
import           Data.Attoparsec.ByteString (Parser, parseOnly)
import qualified Data.Attoparsec.ByteString as A
import qualified Data.ByteString            as BS
import           Data.ByteString.Builder    (Builder, byteString,
                                             toLazyByteString)
import qualified Data.ByteString.Builder    as BB
import qualified Data.ByteString.Lazy       as BL
import           Data.Proxy
import           Data.Monoid                ((<>))
import           Data.Word                  (Word8)
import           GHC.TypeLits

-- TODO: Make injective
class (Show h, HashAlgorithm h) => MultihashAlgorithm h where
  type Tag h :: Nat
  type Len h :: Nat

instance MultihashAlgorithm SHA1 where
  type Tag SHA1 = 0x11
  type Len SHA1 = 20

instance MultihashAlgorithm SHA256 where
  type Tag SHA256 = 0x12
  type Len SHA256 = 32

instance MultihashAlgorithm SHA512 where
  type Tag SHA512 = 0x13
  type Len SHA512 = 64

instance MultihashAlgorithm SHA3_512 where
  type Tag SHA3_512 = 0x14
  type Len SHA3_512 = 64

instance MultihashAlgorithm SHA3_384 where
  type Tag SHA3_384 = 0x16
  type Len SHA3_384 = 48

instance MultihashAlgorithm SHA3_256 where
  type Tag SHA3_256 = 0x16
  type Len SHA3_256 = 32

instance MultihashAlgorithm SHA3_224 where
  type Tag SHA3_224 = 0x17
  type Len SHA3_224 = 28


data RawDigest = RawDigest
    { algorithm :: !Word8
    , length    :: !Word8
    , digest    :: !BS.ByteString
    } deriving (Show, Eq)


data Digest = forall h. (KnownNat (Tag h), MultihashAlgorithm h) => Digest (CH.Digest h)

tag :: forall h proxy. (KnownNat (Tag h), MultihashAlgorithm h) => proxy h -> Word8
tag d = fromIntegral $ natVal (Proxy :: Proxy (Tag h))


encode :: (KnownNat (Tag h), MultihashAlgorithm h) => CH.Digest h -> BL.ByteString
encode = toLazyByteString . encoder

decode :: BS.ByteString -> Either String Digest
decode = parseOnly decoder

encoder :: (KnownNat (Tag h), MultihashAlgorithm h) => CH.Digest h -> Builder
encoder = encoderRaw . encodeTag

decoder :: Parser (Digest)
decoder = decodeTag <$> decoderRaw

encodeTag :: forall h. (KnownNat (Tag h), MultihashAlgorithm h) => CH.Digest h -> RawDigest
encodeTag d = RawDigest
  (tag d)
  (fromIntegral $ hashDigestSize (undefined :: h))
  (BS.pack $ _ $ show d)

decodeTag :: RawDigest -> Digest
decodeTag = _

encoderRaw :: RawDigest -> Builder
encoderRaw d =  BB.word8 (algorithm d)
  <> BB.word8 (length d)
  <> byteString (digest d)

decoderRaw :: Parser RawDigest
decoderRaw = do
  h <- A.anyWord8
  l <-  A.anyWord8
  d <- A.take (fromIntegral l)
  return $ RawDigest h l d
