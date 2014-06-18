module Network.Wai.Middleware.Session.Stateless.Types where
import Data.ByteString (ByteString)

type ParameterValidator = ByteString -> Bool

type ParametersValidator = ByteString -> Bool
