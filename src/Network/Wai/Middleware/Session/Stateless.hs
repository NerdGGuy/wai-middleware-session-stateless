{-# LANGUAGE CPP, OverloadedStrings, FlexibleInstances #-}
module Network.Wai.Middleware.Session.Stateless ( setSession, session, clearSession, SessionConfig(..), SetSessionConfig(..) ) where

import qualified Crypto.Hash as CRYPTO (hmac, HMAC, SHA256)
import Data.SecureMem
import Network.Wai.Middleware.Cookie
import Data.Default
import Network.Wai (Middleware, Application)
import Web.Cookie (parseCookies, renderSetCookie, SetCookie(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (concat)
import Data.ByteString.Base64
import Data.Either
import Data.Monoid
import Data.Byteable
import Data.List (sort)

data SessionConfig =
    SessionConfig {
        parameters :: [ByteString],
        hmacKey :: ByteString
    }

data SetSessionConfig =
    SetSessionConfig {
        setParameters :: [(ByteString,ByteString)],
        setHMACKey :: ByteString,
        salt :: SecureMem
    }

instance Default SessionConfig where
    def = SessionConfig ["name", "expiry"] "hmac"

instance Byteable [ByteString] where
    toBytes x = BS.concat x

setSecureCookie (name,value) = setCookie def { setCookieName = name, setCookieValue = value, setCookieHttpOnly = True, setCookieSecure = True }
setInsecureCookie (name,value) = setCookie def { setCookieName = name, setCookieValue = value }
setNullCookie name = setCookie def { setCookieName = name, setCookieValue = "" }

-- todo: compute hash in securemem
calcHMAC salt x = encode $ toBytes (CRYPTO.hmac (toBytes salt) (toBytes x) :: CRYPTO.HMAC CRYPTO.SHA256)

setSession :: SetSessionConfig -> Middleware
setSession config app = foldr (\x app -> setInsecureCookie x app) (setSessionHMAC (setHMACKey config) (salt config) (setParameters config) app) (setParameters config)
    where
        calcSessionHMAC salt x = calcHMAC salt (snd $ unzip $ sort x)
        setSessionHMAC hmacname salt x = setSecureCookie (hmacname,calcSessionHMAC salt x)

-- expireSession :: (ByteString,ByteString) -> Middleware
-- expireSession expires = setSessionExpires expires

session :: SessionConfig -> ([(ByteString,ByteString)] -> Bool) -> SecureMem -> Application -> Middleware
session config checkExpires salt sessionapp sessionlessapp req =
    case cookies req of
        Just cookiesValue ->
            case checkExpires cookiesValue of
                True -> case lookupCookie (hmacKey config) req of
                    Just hash -> case (sessionString (parameters config) req) of
                        Just expectedSessionString -> (sessionHash hash salt expectedSessionString sessionapp sessionlessapp) req
                        Nothing -> sessionlessapp req
                    Nothing -> sessionlessapp req
                False -> foldr (\x a -> setNullCookie x a) sessionlessapp (parameters config) req
        Nothing -> sessionlessapp req
        where
            lookupCookie name req = lookup name =<< (cookies req)
            sessionString x req = do
                cookieslist <- sequence $ fmap ((\req x -> lookupCookie x req) req) x
                return $ BS.concat $ sort cookieslist

clearSession x app req = foldr (\x a -> setNullCookie x a) app x req

sessionHash :: ByteString -> SecureMem -> ByteString -> Application -> Middleware
sessionHash b64hash salt sessionstring sessionapp sessionlessapp =
    case toBytes (CRYPTO.hmac (toBytes salt) sessionstring :: CRYPTO.HMAC CRYPTO.SHA256) of
        x | x == case decode b64hash of
            Right hash -> hash
            Left err -> ""
            -> sessionapp
          | otherwise -> sessionlessapp
