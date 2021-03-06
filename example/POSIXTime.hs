{-# LANGUAGE CPP, TemplateHaskell, OverloadedStrings, ScopedTypeVariables #-}
module Main where

--import Network (withSocketsDo)
import Network.Wai
import Network.HTTP.Types (status200, status302, status400, status404)
import Network.Wai.Handler.Warp (run, defaultSettings, settingsPort)
import Network.Wai.Handler.WarpTLS (runTLS, tlsSettings)
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as BS
import Data.Maybe
import Network.Wai.Middleware.Session.Stateless
import Network.Wai.Middleware.Session.Stateless.NOnce.POSIXTime
import Data.SecureMem
import Network.Wai.Middleware.CleanPath
import Data.Text (Text)
import Data.Monoid (mempty)
import Data.Text.Encoding
import Data.Default
import Control.Monad.IO.Class
import Data.Text.Encoding
import Network.HTTP.Conduit (Manager, newManager, conduitManagerSettings)


import           Keys                            (googleKey)
import           Network.OAuth.OAuth2
import           Data.Aeson                      (FromJSON)
import           Data.Aeson.TH                   (deriveJSON, defaultOptions)
import qualified Data.ByteString.Char8           as BSC8
import qualified Data.ByteString.Lazy.Internal   as BL
import           Prelude                         hiding (id)
import qualified Prelude                         as P (id)

--------------------------------------------------

data Token = Token { issued_to      :: Text
                   , audience       :: Text
                   , user_id        :: Maybe Text
                   , scope          :: Text
                   , expires_in     :: Integer
                   , email          :: Maybe Text
                   , verified_email :: Maybe Bool
                   , access_type    :: Text
                   } deriving (Show)

$(deriveJSON defaultOptions ''Token)

data User = User { id          :: Text
                 , name        :: Text
                 , given_name  :: Text
                 , family_name :: Text
                 , link        :: Text
                 , picture     :: Text
                 , gender      :: Text
                 , birthday    :: Text
                 , locale      :: Text
                 } deriving (Show)

$(deriveJSON defaultOptions ''User)

--------------------------------------------------

login :: BSC8.ByteString -> Middleware
login email app req sendResponse = do
    nonce <- liftIO setSessionNOncePOSIXTimeNow
    setSession (SetSessionConfig  [("email", email)] nonce "HMAC" getKey) app req sendResponse

redirect302 :: BS.ByteString -> Application
redirect302 uri _ sendResponse = sendResponse $ responseLBS status302 [("Location", uri)] mempty

error400 :: Application
error400 _ sendResponse = sendResponse $ responseLBS status400 [] mempty

sessionApp :: Manager -> [Text] -> Application
sessionApp _ [] req sendResponse = appSession req sendResponse
sessionApp _ ["error"] req sendResponse = error400 req sendResponse
sessionApp _ ["login"] req sendResponse = redirect302 (authorizationUrl googleKey `appendQueryParam` googleScopeEmail `appendQueryParam` googleState) req sendResponse
sessionApp _ ["logout"] req sendResponse = appUnSetSession (application "logout") req sendResponse
sessionApp mgr ["googleCallback"] req sendResponse = sessionGoogleCallback mgr req sendResponse -- (\req -> return $ responseLBS status200 [("Content-Type", "text/plain")] $ fromString $ show $ fst $ head $ queryString req)
sessionApp _ _ req sendResponse = notFound req sendResponse

sessionGoogleCallback :: Manager -> Application
sessionGoogleCallback mgr req sendResponse =
    case lookupQuery "state" of
        Just mstate ->
            case mstate of
                Just state ->
                    case checkState state of
                        True ->
                            case lookupQuery "code" of
                                Just mcode ->
                                    case mcode of
                                        Just code -> do
                                            fetch <- fetchAccessToken mgr googleKey code
                                            case fetch of
                                                Right token -> do --FIXME, a "something went wrong" error can happen if the code is wrong
                                                    tokeninfo <- authGetJSON mgr token "https://www.googleapis.com/oauth2/v1/tokeninfo" --application (L.fromStrict $ accessToken token) req
                                                    case tokeninfo of
                                                        Right (info :: Token) -> do
                                                            case verified_email info of
                                                                Just True -> case email info of
                                                                    Just emailtext -> (login $ encodeUtf8 emailtext) (application "login") req sendResponse -- application (L.fromStrict $ encodeUtf8 emailtext) req
                                                                    Nothing -> error400 req sendResponse
                                                                Just False -> application "emailnotverified" req sendResponse
                                                                Nothing -> error400 req sendResponse
                                                        Left tokenerror -> application "tokenerror" req sendResponse
                                                Left fetchError -> application "fetcherror" req sendResponse --FIXME, get "something went wrong" error to fail here and use fetchError
                                        Nothing -> error400 req sendResponse
                                Nothing -> error400 req sendResponse
                        False -> error400 req sendResponse
                Nothing -> error400 req sendResponse
        Nothing -> error400 req sendResponse
    where
        lookupQuery name = lookup name (queryString req)

appSession :: Application
appSession req sendResponse = do
  nonce <- liftIO $ sessionNOncePOSIXTimeNow (30)
  session (SessionConfig [("email",(\x -> True))] nonce "HMAC" getKey) (application "session") (application "sessionless") req sendResponse

appUnSetSession :: Middleware
appUnSetSession = clearSession ["email","expire"]

application :: L.ByteString -> Application
application x _ sendResponse = sendResponse $ responseLBS status200 [("Content-Type", "text/plain")] x

appfile x y = responseFile status200 y x Nothing

notFound _ sendResponse = sendResponse $ responseLBS status404 [("Content-Type", "text/plain")] "404 Not Found"

getKey :: SecureMem
getKey = secureMemFromByteString "00000000000000000000000000000000"

filterPath x = Right x

-- | Gain read-only access to basic profile information, including a
googleScopeUserInfo :: QueryParams
googleScopeUserInfo = [("scope", "email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email")]

googleScopeEmail :: QueryParams
googleScopeEmail = [("scope", "email")]

googleState :: QueryParams
googleState = [("state", "00000000")]

checkState :: BSC8.ByteString -> Bool
checkState = (==) "00000000"

-- | Token Validation
--validateToken :: AccessToken -> IO (OAuth2Result BL.ByteString)
--validateToken token = authGetBS token "https://www.googleapis.com/oauth2/v1/tokeninfo"

--validateToken' :: FromJSON a => AccessToken -> IO (OAuth2Result a)
--validateToken' token = authGetJSON token "https://www.googleapis.com/oauth2/v1/tokeninfo"

-- | fetch user email.
--   for more information, please check the playround site.
--
--userinfo :: AccessToken -> IO (OAuth2Result BL.ByteString)
--userinfo token = authGetBS token "https://www.googleapis.com/oauth2/v2/userinfo"

--userinfo' :: FromJSON a => AccessToken -> IO (OAuth2Result a)
--userinfo' token = authGetJSON token "https://www.googleapis.com/oauth2/v2/userinfo"

--normalCase :: IO ()
--normalCase = do
--    BSC8.putStrLn $ authorizationUrl googleKey `appendQueryParam` googleScopeUserInfo
--    putStrLn "visit the url and paste code here: "
--    code <- fmap BSC8.pack getLine
--    (Right token) <- fetchAccessToken googleKey code
--    putStr "AccessToken: " >> print token
--    -- get response in ByteString
--    validateToken token >>= print
--    -- get response in JSON
--    (validateToken' token :: IO (OAuth2Result Token)) >>= print
--    -- get response in ByteString
--    userinfo token >>= print
--    -- get response in JSON
--    (userinfo' token :: IO (OAuth2Result User)) >>= print

main = do
    mgr <- newManager conduitManagerSettings
    runTLS (tlsSettings  "certificate.pem" "key.pem") defaultSettings { settingsPort = 443 } $ cleanPath filterPath "" $ sessionApp mgr

