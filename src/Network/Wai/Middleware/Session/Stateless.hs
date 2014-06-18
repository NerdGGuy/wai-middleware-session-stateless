{-# LANGUAGE CPP, OverloadedStrings, FlexibleInstances #-}
module Network.Wai.Middleware.Session.Stateless ( setSession, session, clearSession, SessionConfig(..), SetSessionConfig(..), defSetSessionConfig ) where

import Network.Wai.Middleware.Session.Stateless.Types
import Network.Wai.Middleware.Session.Stateless.NOnce.POSIXTime
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
import Network.Wai
import Network.HTTP.Types

-- type ParameterValidator = ByteString -> Bool

-- type ParametersValidator = ByteString -> Bool

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

defSessionConfig = SessionConfig [("username", (\x -> True))] [] "HMAC"

defSetSessionConfig = (\name expiry key -> SetSessionConfig [("username", name)] [] "HMAC" key)

instance Byteable [ByteString] where
    toBytes x = BS.concat x

setSecureCookie (name,value) = setCookie def { setCookieName = name, setCookieValue = value, setCookieHttpOnly = True, setCookieSecure = True }
setInsecureCookie (name,value) = setCookie def { setCookieName = name, setCookieValue = value }
setNullCookie name = setCookie def { setCookieName = name, setCookieValue = "" }

-- todo: compute hash in securemem
calcHMAC key x = encode $ toBytes (CRYPTO.hmac (toBytes key) (toBytes x) :: CRYPTO.HMAC CRYPTO.SHA256)

setSession :: SetSessionConfig -> Middleware
setSession config app = setSessionParameterCookies $ setSessionNOnceCookies (setSessionHMAC (setSessionHMACKey config) (setSessionKey config) (setSessionParameters config) app)
    where
        calcSessionHMAC key x = calcHMAC key (snd $ unzip $ sort x)
        setSessionHMAC hmacname key x = setSecureCookie (hmacname,calcSessionHMAC key x)
        setSessionParameterCookies app = foldr (\x app -> setInsecureCookie x app) app (setSessionNOnce config)
        setSessionNOnceCookies app = foldr (\x app -> setSecureCookie x app) app (setSessionParameters config)

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
            let calcHMAC = (CRYPTO.hmac (toBytes $ sessionKey config) ss) :: CRYPTO.HMAC CRYPTO.SHA256
            let sessionHMAC = encode $ toBytes calcHMAC
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

clearSession x app req = foldr (\x a -> setNullCookie x a) app x req
