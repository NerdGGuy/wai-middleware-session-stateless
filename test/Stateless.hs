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

import Control.Monad (unless)
import System.Exit (exitFailure)
import Test.QuickCheck.All (quickCheckAll)
import Test.QuickCheck (Property)
import Test.QuickCheck.Monadic (assert, monadicIO, run)
import Network.Wai.Test (defaultRequest, request, runSession, simpleBody, simpleHeaders, SResponse)

-- request utils --
testSessionRequest :: BS.ByteString -> Request
testSessionRequest hash = defaultRequest { requestHeaders = (mk "Cookie", BS.concat ["name=username; expires=00000000; hash=",hash,";"]):(requestHeaders defaultRequest) }

-- response utils --
response x = responseLBS status200 [("Content-Type", "text/plain")] x

-- app utils --
app :: ByteString -> Application
app x req = do return $ response x

checkExpiry :: [(BS.ByteString,BS.ByteString)] -> Bool
checkExpiry x = case lookup "expires" x of
                    Just "00000000" -> True
                    Just _ -> False
                    Nothing -> False

getSalt :: SecureMem
getSalt = secureMemFromByteString "00000000000000000000000000000000"

-- response utils --
simpleHash :: [SetCookie] -> Maybe BS.ByteString
simpleHash scookies = do
    hash <- find (\x -> setCookieName x == "hash") scookies
    return $ setCookieValue hash

simpleSetCookie :: SResponse -> [SetCookie]
simpleSetCookie res = fmap parseSetCookie $ snd (unzip $ filter (\(x,y) -> (mk "Set-Cookie") == x) (simpleHeaders res))

-- test functions --
appSession :: Application
appSession = session (SessionConfig ["name","expires"] "hash") checkExpiry getSalt (app "session") (app "sessionless")

appSetSession :: Application
appSetSession = setSession (SetSessionConfig [("name","username"),("expires","00000000")] "hash" getSalt) (app "")

-- tests --
prop_testSessionless :: String -> Property
prop_testSessionless hash = monadicIO $ do
    testres <- run $ runSession (request $ testSessionRequest $ BSC8.pack hash) (appSession)
    expectedres <- run $ runSession (request $ testSessionRequest $ BSC8.pack hash) (app "sessionless")
    assert $ (simpleBody expectedres) == (simpleBody testres)

prop_testSession :: Property
prop_testSession = monadicIO $ do
    setres <- run $ runSession (request $ testSessionRequest $ BSC8.pack "") (appSetSession)
    let mHash = simpleHash $ simpleSetCookie setres
    -- run $ print (show $ hash mHash)
    testres <- run $ runSession (request $ testSessionRequest $ hash mHash) (appSession)
    expectedres <- run $ runSession (request $ testSessionRequest $ hash mHash) (app "session")
    assert $ (simpleBody expectedres) == (simpleBody testres)
    where
        hash (Just hash) = hash
        hash Nothing = BSC8.pack ""

main = do
    allPass <- $quickCheckAll -- Run QuickCheck on all prop_ functions
    unless allPass exitFailure
