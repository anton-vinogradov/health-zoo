"""Atomic JSON state with rollback; a successful write means durable state."""
from contextlib import contextmanager
from functools import wraps
import copy
import json
import os
import tempfile


class StateSaveError(RuntimeError):
    """The requested change was not saved or applied."""


def write_json(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    temporary = None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory,
                                         prefix='.health-zoo-', delete=False) as stream:
            temporary = stream.name
            json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except (OSError, ValueError) as exc:
        raise StateSaveError('Не удалось сохранить состояние; изменения не применены.') from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def locked(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return call


class PersistentJSON:
    def _storage_init(self, attribute):
        self._state_attribute = attribute
        self._persisted = copy.deepcopy(getattr(self, attribute))
        self._in_transaction = False
        self.storage_error = getattr(self, 'storage_error', '')

    def _persist(self, strict=True):
        if self._in_transaction:
            return
        candidate = getattr(self, self._state_attribute)
        try:
            write_json(self.path, candidate)
        except StateSaveError:
            if strict:
                setattr(self, self._state_attribute, copy.deepcopy(self._persisted))
            else:
                # Maintenance remains effective in memory even if disk is full.
                self._persisted = copy.deepcopy(candidate)
            self.storage_error = 'Состояние не сохраняется: проверьте доступ к ' + self.path
            if strict:
                raise
        else:
            self._persisted = copy.deepcopy(candidate)
            self.storage_error = ''

    @contextmanager
    def transaction(self):
        with self.lock:
            previous = copy.deepcopy(getattr(self, self._state_attribute))
            self._in_transaction = True
            try:
                yield self
                self._in_transaction = False
                self._persist()
            except Exception:
                setattr(self, self._state_attribute, previous)
                raise
            finally:
                self._in_transaction = False
