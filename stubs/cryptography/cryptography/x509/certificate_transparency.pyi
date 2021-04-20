import abc
import datetime
from enum import Enum

class LogEntryType(Enum):
    X509_CERTIFICATE: int = ...
    PRE_CERTIFICATE: int = ...

class Version(Enum):
    v1: int = ...

class SignedCertificateTimestamp(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def version(self) -> Version: ...
    @property
    @abc.abstractmethod
    def log_id(self) -> bytes: ...
    @property
    @abc.abstractmethod
    def timestamp(self) -> datetime.datetime: ...
    @property
    @abc.abstractmethod
    def entry_type(self) -> LogEntryType: ...
