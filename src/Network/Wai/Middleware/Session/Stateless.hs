{-# LANGUAGE CPP, OverloadedStrings, FlexibleInstances #-}
module Network.Wai.Middleware.Session.Stateless ( setSession, session, clearSession, SessionConfig(..), SetSessionConfig(..) ) where

import Network.Wai.Middleware.Session.Stateless.Types
import qualified Crypto.Hash as CRYPTO (hmac, HMAC, SHA256)
import Data.SecureMem
import Network.Wai.Middleware.Cookie
import Data.Default
import Web.Cookie (SetCookie(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (concat)
import Data.ByteString.Base64
import Data.Byteable
import Data.List (sort)
import Network.Wai

data SessionConfig =
    SessionConfig {
        sessionParameters :: [(ByteString,ParameterValidator)],
        sessionNOnce :: [(ByteString,ParameterValidator)],
        sessionHMACKey :: ByteString,
        sessionKey :: SecureMem
    }

data SetSessionConfig =
    SetSessionConfig {
        setSessionParameters :: [(ByteString,ByteString)],
        setSessionNOnce :: [(ByteString,ByteString)],
        setSessionHMACKey :: ByteString,
        setSessionKey :: SecureMem
    }

instance Byteable [ByteString] where
    toBytes x = BS.concat x

setSecureCookie :: (ByteString, ByteString) -> Middleware
setSecureCookie (name,value) = setCookie def { setCookieName = name, setCookieValue = value, setCookieHttpOnly = True, setCookieSecure = True }

setInsecureCookie :: (ByteString, ByteString) -> Middleware
setInsecureCookie (name,value) = setCookie def { setCookieName = name, setCookieValue = value }

setNullCookie :: ByteString -> Middleware
setNullCookie name = setCookie def { setCookieName = name, setCookieValue = "" }

-- todo: compute hash in securemem
calcHMAC :: (Byteable a, Byteable a1) => a -> a1 -> ByteString
calcHMAC key x = encode $ toBytes (CRYPTO.hmac (toBytes key) (toBytes x) :: CRYPTO.HMAC CRYPTO.SHA256)

setSession :: SetSessionConfig -> Middleware
setSession config app = setSessionParameterCookies $ setSessionNOnceCookies (setSessionHMAC (setSessionHMACKey config) (setSessionKey config) (setSessionParameters config) app)
    where
        calcSessionHMAC key x = calcHMAC key (snd $ unzip $ sort x)
        setSessionHMAC hmacname key x = setSecureCookie (hmacname,calcSessionHMAC key x)
        setSessionParameterCookies _app = foldr (\x _app_ -> setInsecureCookie x _app_) _app (setSessionNOnce config)
        setSessionNOnceCookies _app = foldr (\x _app_ -> setSecureCookie x _app_) _app (setSessionParameters config)

session :: SessionConfig -> Application -> Middleware
session config sessionapp sessionlessapp req =
    case validateParameters of
        Just True ->
            case validateSession of
                Just True -> sessionapp req
                Just False -> sessionlessapp req
                Nothing -> sessionlessapp req
        Just False -> sessionlessapp req
        Nothing -> sessionlessapp req
    where
        validateParameters =
           foldr
               (\x y -> do
                   v <- validateParameter x
                   b <- y
                   return $ (&&) b v)
               (Just True)
               $ (sessionParameters config) ++ (sessionNOnce config)
        validateParameter x = do
            c <- lookupCookie (fst x)
            return $ (snd x) c
        validateSession = do
            ss <- sessionString
            let sha256HMAC = (CRYPTO.hmac (toBytes $ sessionKey config) ss) :: CRYPTO.HMAC CRYPTO.SHA256
            let sessionHMAC = encode $ toBytes sha256HMAC
            clientHMAC <- lookupCookie (sessionHMACKey config)
            return $ sessionHMAC == clientHMAC
          where
            sessionString = do
                sessionstring <- foldr
                    (\x y -> do
                        c <- (lookupCookie (fst x))
                        s <- y
                        return $ BS.concat [s,c])
                    (Just "")
                    (sessionParameters config)
                return sessionstring
        lookupCookie name = lookup name =<< (cookies req)

clearSession :: [ByteString]
                -> (Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived)
                -> Request
                -> (Response -> IO ResponseReceived)
                -> IO ResponseReceived
clearSession x app req = foldr (\x' a -> setNullCookie x' a) app x req
