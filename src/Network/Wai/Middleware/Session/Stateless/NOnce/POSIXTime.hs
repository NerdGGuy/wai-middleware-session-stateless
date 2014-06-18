{-# LANGUAGE OverloadedStrings, ViewPatterns #-}
module Network.Wai.Middleware.Session.Stateless.NOnce.POSIXTime (sessionNOncePOSIXTime, sessionNOncePOSIXTimeNow, setSessionNOncePOSIXTime, setSessionNOncePOSIXTimeNow) where
import Network.Wai.Middleware.Session.Stateless.Types
import Data.ByteString.Char8
import Data.Time
import Data.Time.Clock.POSIX

sessionNOncePOSIXTime :: POSIXTime -> Int -> [(ByteString, ParameterValidator)]
sessionNOncePOSIXTime time seconds =
    [
        ("expire",
        (\x -> case Data.ByteString.Char8.readInt x of
            Just (i, x) -> case ((Data.ByteString.Char8.length x) == 0) of
                True -> (i <= (round time)) && (i >= ((round time) - seconds))
                False -> False
            Nothing -> False)
        )
    ]

sessionNOncePOSIXTimeNow :: Int -> IO [(ByteString, ParameterValidator)]
sessionNOncePOSIXTimeNow seconds = do
    now <- getPOSIXTime
    return $ sessionNOncePOSIXTime now seconds

setSessionNOncePOSIXTime :: POSIXTime -> [(ByteString, ByteString)]
setSessionNOncePOSIXTime time = [("expire", pack $ show $ (round time :: Int))]

setSessionNOncePOSIXTimeNow :: IO [(ByteString, ByteString)]
setSessionNOncePOSIXTimeNow = do
    now <- getPOSIXTime
    return $ setSessionNOncePOSIXTime now
