"""Loopback reference services for the bundled protocol seed corpora."""
import argparse
import ctypes
import logging
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = Path(__file__).resolve().parent / '.cache'


def stop(signum, frame):
    raise SystemExit(0)


def binary(name, relative):
    target = shutil.which(name) or str(CACHE / relative)
    if not os.access(target, os.X_OK):
        raise RuntimeError(f'Missing {name}; run aflnet-ui/targets/setup_targets.sh')
    return target


def stop_with_parent():
    # Native subprocesses must not survive a fuzzer timeout killing their launcher.
    parent = os.getppid()
    if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'Unable to set parent-death signal')
    if os.getppid() != parent:
        os.kill(os.getpid(), signal.SIGTERM)


def ftp(port, directory):
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer

    authorizer = DummyAuthorizer()
    authorizer.add_user('ubuntu', 'ubuntu', directory, perm='elradfmwMT')
    authorizer.add_anonymous(directory)
    FTPHandler.authorizer = authorizer
    FTPHandler.timeout = 2
    with FTPServer(('127.0.0.1', port), FTPHandler) as server:
        server.serve_forever(timeout=.1)


def dicom(port, directory):
    from pynetdicom import AE, evt, AllStoragePresentationContexts
    from pynetdicom.sop_class import (Verification, PatientRootQueryRetrieveInformationModelFind,
                                    PatientRootQueryRetrieveInformationModelGet,
                                    StudyRootQueryRetrieveInformationModelFind,
                                    StudyRootQueryRetrieveInformationModelGet)

    def store(event):
        dataset = event.dataset
        dataset.file_meta = event.file_meta
        dataset.save_as(Path(directory) / f'{event.request.MessageID}.dcm', enforce_file_format=True)
        return 0x0000

    def find(event):
        yield 0x0000, None

    def get(event):
        yield 0

    ae = AE(ae_title='ANY-SCP')
    ae.maximum_pdu_size = 16384
    ae.network_timeout = 2
    ae.dimse_timeout = 2
    ae.acse_timeout = 2
    ae.add_supported_context(Verification)
    for context in AllStoragePresentationContexts:
        ae.add_supported_context(context.abstract_syntax, context.transfer_syntax)
    for sop_class in (PatientRootQueryRetrieveInformationModelFind, PatientRootQueryRetrieveInformationModelGet,
                      StudyRootQueryRetrieveInformationModelFind, StudyRootQueryRetrieveInformationModelGet):
        ae.add_supported_context(sop_class)
    ae.start_server(('127.0.0.1', port), evt_handlers=[(evt.EVT_C_ECHO, lambda event: 0x0000),
                    (evt.EVT_C_STORE, store), (evt.EVT_C_FIND, find), (evt.EVT_C_GET, get)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('protocol', choices=['FTP', 'DNS', 'DICOM', 'IPP'])
    parser.add_argument('port', type=int)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Local reference services require a port between 1024 and 65535')
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logging.basicConfig(level=logging.ERROR)
    with tempfile.TemporaryDirectory(prefix='protocol-reference-') as directory:
        if args.protocol == 'FTP':
            ftp(args.port, directory)
        elif args.protocol == 'DICOM':
            dicom(args.port, directory)
        elif args.protocol == 'DNS':
            command = [binary('dnsmasq', 'system/usr/sbin/dnsmasq'), '--no-daemon', '--conf-file=/dev/null',
                       f'--port={args.port}', '--listen-address=127.0.0.1', '--bind-interfaces', '--no-resolv',
                       '--no-hosts', '--address=/#/127.0.0.1', '--local-ttl=0', f'--pid-file={directory}/dns.pid']
        else:
            command = [binary('ippeveprinter', 'system/usr/sbin/ippeveprinter'), '-r', 'off', '-n', 'localhost',
                       '-p', str(args.port), '-f', 'text/plain,application/octet-stream', '-d', directory, 'Protocol Printer']
        if args.protocol in {'DNS', 'IPP'}:
            process = subprocess.Popen(command, preexec_fn=stop_with_parent)
            try:
                raise SystemExit(process.wait())
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == '__main__':
    main()
