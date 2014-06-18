{-# LANGUAGE TemplateHaskell, OverloadedStrings #-}

import Data.Unique (newUnique, hashUnique)
import Data.Ratio (numerator, denominator)
import Data.String (fromString)
import Network.HTTP.Types (status200)
import Network.Wai (Application, Middleware, Request(..), Response(..), responseLBS, responseSource)
import Web.Cookie (parseCookies, parseSetCookie, renderSetCookie, SetCookie(..), Cookies(..), setCookieName)

import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString as BS  (ByteString,concat,breakSubstring)
import qualified Data.ByteString.Char8 as BSC8 (pack)
import Data.List (find)
import Data.SecureMem

import Data.CaseInsensitive (mk)
import Network.Wai.Middleware.Session.Stateless
import Network.Wai.Middleware.Session.Stateless.NOnce.POSIXTime

import Control.Monad (unless)
import System.Exit (exitFailure)
import Test.QuickCheck.All (quickCheckAll)
import Test.QuickCheck (Property)
import Test.QuickCheck.Monadic (assert, monadicIO, run)
import Network.Wai.Test (defaultRequest, request, runSession, simpleBody, simpleHeaders, SResponse)

-- request utils --
--testSessionRequest :: BS.ByteString -> IO Request
--testSessionRequest hash = do return $ defaultRequest { requestHeaders = (mk "Cookie", BS.concat ["username=username; expiry=00000000; HMAC=",hash,";"]):(requestHeaders defaultRequest) }
testSessionRequest :: [(BS.ByteString, BS.ByteString)] -> IO Request
testSessionRequest xs = do
    return $ defaultRequest { requestHeaders = (mk "Cookie", cookiesToString xs):(requestHeaders defaultRequest) }
    where
        cookieToString (k,v) = BS.concat [k,"=",v,";"]
        cookiesToString = foldl (\xs x -> BS.concat [cookieToString x,xs]) ""

testSessionRequestHMAC :: BS.ByteString -> IO Request
testSessionRequestHMAC hmac = testSessionRequest [("username","username"), ("expire","00000000"), ("HMAC",hmac)]

-- response utils --
response x = responseLBS status200 [("Content-Type", "text/plain")] x

-- app utils --
app :: ByteString -> Application
app x req = do return $ response x

--checkExpiry :: [(BS.ByteString,BS.ByteString)] -> Bool
--checkExpiry x = case lookup "expiry" x of
--                    Just "00000000" -> True
--                    Just _ -> False
--                    Nothing -> False

getSalt :: SecureMem
getSalt = secureMemFromByteString "00000000000000000000000000000000"

-- response utils --
simpleHMAC :: [SetCookie] -> Maybe BS.ByteString
simpleHMAC scookies = do
    hmac <- find (\x -> setCookieName x == "HMAC") scookies
    return $ setCookieValue hmac

simpleExpire :: [SetCookie] -> Maybe BS.ByteString
simpleExpire scookies = do
    expire <- find (\x -> setCookieName x == "expire") scookies
    return $ setCookieValue expire

simpleSetCookie :: SResponse -> [SetCookie]
simpleSetCookie res = fmap parseSetCookie $ snd (unzip $ filter (\(x,y) -> (mk "Set-Cookie") == x) (simpleHeaders res))

-- test functions --
appSession :: Application
appSession = session (SessionConfig [("username",(\x -> True))] [("expire",validateExpiry)] "HMAC" getSalt) (app "session") (app "sessionless")
    where
        validateExpiry "00000000" = True
        validateExpiry _ = False

appSetSession :: Application
appSetSession = setSession (SetSessionConfig [("username","username")] [("expire","00000000")] "HMAC" getSalt) (app "")

appSetSessionNOncePOSIXTime :: IO Application
appSetSessionNOncePOSIXTime = do
    nonce <- setSessionNOncePOSIXTimeNow
    return $ setSession (SetSessionConfig [("username","username")] nonce "HMAC" getSalt) (app "")

-- tests --
prop_testSessionless :: String -> Property
prop_testSessionless hmac = monadicIO $ do
    testreq <- run $ testSessionRequestHMAC $ BSC8.pack hmac
    testres <- run $ runSession (request $ testreq) (appSession)
    expectedres <- run $ runSession (request $ testreq) (app "sessionless")
    assert $ (simpleBody expectedres) == (simpleBody testres)

prop_testSession :: Property
prop_testSession = monadicIO $ do
    --setses <- run $ testSessionRequestHMAC $ BSC8.pack ""
    setres <- run $ runSession (request $ defaultRequest) (appSetSession)
    let mHash = simpleHMAC $ simpleSetCookie setres
    --run $ print (show $ hash mHash)
    testses <- run $ testSessionRequestHMAC $ hash mHash
    testres <- run $ runSession (request $ testses) (appSession)
    expectedres <- run $ runSession (request $ testses) (app "session")
    assert $ (simpleBody expectedres) == (simpleBody testres)
    where
        hash (Just hash) = hash
        hash Nothing = BSC8.pack ""

posixTimeSession :: IO Application
posixTimeSession = do
    nonceposixtime <- sessionNOncePOSIXTimeNow (1)
    return $ session (SessionConfig [("username",(\x -> True))] nonceposixtime "HMAC" getSalt) (app "session") (app "sessionless")

prop_testNOncePOSIXTime :: Property
prop_testNOncePOSIXTime = monadicIO $ do
    appsettime <- run $ appSetSessionNOncePOSIXTime
    setres <- run $ runSession (request $ defaultRequest) (appsettime)
    let mHash = simpleHMAC $ simpleSetCookie setres
    let mExpire = simpleExpire $ simpleSetCookie setres
    run $ print (show $ simpleExpire $ simpleSetCookie setres)
    testses <- run $ testSessionRequest [("username","username"),("HMAC", hash mHash), ("expire", expire mExpire)]
    posixapp <- run $ posixTimeSession
    testres <- run $ runSession (request $ testses) (posixapp)
    expectedres <- run $ runSession (request $ testses) (app "session")
    assert $ (simpleBody expectedres) == (simpleBody testres)
    where
        hash (Just hash) = hash
        hash Nothing = BSC8.pack ""
        expire (Just expire) = expire
        expire Nothing = BSC8.pack ""



main = do
    allPass <- $quickCheckAll -- Run QuickCheck on all prop_ functions
    unless allPass exitFailure
