
from argparse import ArgumentParser

from json import load, loads, dumps, JSONDecodeError

from ipaddress import ip_address
from urllib.parse import urlparse

from os import remove
from sqlite3 import connect
from socket import AF_INET, AF_INET6, AF_UNIX, SOCK_DGRAM, socket

def filter(inpt):
    """
    The place for custom filter logic. Packets filtered out here will be
    counted against neither the per-batch not the total packet limits.
    """
    # if inpt.get('msg') != 'Address spoofing':
    #     return False
    return True

def main():
    """
    Entry point. Performs:
        - Argument and config parsing
        - Database setup
    Execution then continues with the actual
    listening and parsing in listen_and_write(...) .
    """
    print("Hello, world!")
    args = parse_arguments()
    cfg = load_config(args)
    if args.wipe_existing:
        try:
            remove(cfg.database)
        except FileNotFoundError:
            pass
    conn = connect(cfg.database, isolation_level=None)
    with conn:
        for crt in cfg.create:
            conn.execute(crt)
    listen_and_write(cfg, conn, total=args.total, verbose=args.verbose)

def listen_and_write(cfg, conn, total=float('inf'), verbose=False):
    """
    Sets up the listening socket and kicks off processing.
    The per-batch and total limits are managed here.
    """
    if cfg.bind is None:
        raise RuntimeError('Need bind configuration to listen')
    sck = socket(family=cfg.bind[0], type=SOCK_DGRAM)
    sck.bind(cfg.bind[1])
    count = 0
    batchsize = cfg.batch
    if batchsize == 0:
        write_immediately(
            cfg
            , conn
            , receive_batch(sck, total, verbose=verbose)
            )
        return None
    while count < total: #range(total) would not allow \infty
        write_batch(
            cfg
            , conn
            , receive_batch(sck, batchsize, verbose=verbose)
            )
        count = count + batchsize
    return None

def receive_batch(sck, batchsize, verbose=False):
    """
    Generator that receives, decodes, and yields `batchsize` packets
    matching the filter. Malformed and non-matching packets do not
    count towards that limit.
    """
    count = 0
    while count < batchsize:
        raw = sck.recvfrom(4096)[0]
        try:
            payload = loads(raw)
        except JSONDecodeError:
            continue
        if filter(payload):
            count = count + 1
            if verbose:
                print('Processing:', payload)
            yield payload
    return

def write_immediately(cfg, conn, inpt):
    """
    Writes packets from `inpt` to the database as soon as they come in. Less
    performant, but does not potentially lose packets on program interruption.
    """
    for pld in inpt:
        for insrt in cfg.insert:
            conn.execute(
                insrt
                , {**cfg.defaults, **pld}
                )

def write_batch(cfg, conn, inpt):
    """
    Writes packets from `inpt` to the database in one batch. More performant,
    but loses any packets in the current batch on program interruption.
    """
    for insrt in cfg.insert:
        conn.executemany(
            insrt
            , (
                {**cfg.defaults, **pld}
                for pld in inpt
                )
            )
    return None


class Config():
    """
    A class to hold our configuration.
    """
    def __init__(self, database, create, insert, defaults, batch, exporter, bind):
        """
        Some verification, but mostly just translation of inputs into
        class attributes.
        """
        if database is None:
            raise ValueError('No database file configured!')
        if not isinstance(create, list):
            raise ValueError('No create statement list configured!')
        if not isinstance(insert, list):
            raise ValueError('No insert statement list configured!')
        if not isinstance(batch, int):
            raise ValueError('Invalid batch size', batch)
        if bind is None:
            if exporter is None:
                raise ValueError('Neither bind nor exporter configured!')
            raise NotImplementedError('For now, please attach to the log exporter manually.')
        self.database = database
        self.create = create
        self.insert = insert
        self.defaults = defaults
        self.batch = batch
        self.exporter = exporter
        self.bind = bind
        return None
    def _exporter_to_bind(self):
        """
        Placeholder: Should implement automatic bind configuration detection.
        """
        raise NotImplementedError
    def __repr__(self):
        """
        Dumps all attributes to a dict.
        """
        return {
            'database': self.database
            , 'create': self.create
            , 'insert': self.insert
            , 'defaults': self.defaults
            , 'batch': self.batch
            , 'exporter': self.exporter
            , 'bind': self.bind
            }
    def __str__(self):
        """
        Pretty-printed __repr__ output.
        """
        return dumps(self.__repr__(), indent=2)

def load_config(args):
    """
    Loads the config file and merges it with the arguments to create
    a Config(...) object.
    """
    def first_not_none(*args):
        """
        Literally picks the first arguments that is not None and
        returns it. Defaults to None.

        Basically foldl' (>>=) Nothing for Python's implicit Maybe monad.
        """
        for arg in args:
            if arg is not None:
                return arg
        return None
    if args.config is None:
        cfg = {}
    else:
        with open(args.config, 'r') as handle:
            cfg = load(handle)
    return Config(
        first_not_none(args.database_file, cfg.get('database'))
        , first_not_none(args.create_statement, cfg.get('create'))
        , first_not_none(args.insert_statement, cfg.get('insert'))
        , cfg.get('defaults', {})
        , first_not_none(args.batch, cfg.get('batch'), 0)
        , first_not_none(args.exporter, cfg.get('exporter'))
        , first_not_none(args.bind, parse_bind(cfg.get('bind')))
        )

def parse_arguments():
    """
    Constructs and applies the argument parser.
    """
    parser = ArgumentParser()
    parser.add_argument(
        'config'
        , nargs='?'
        )
    parser.add_argument(
        '-c', '--create-statement'
        , action='append'
        , default=None
        )
    parser.add_argument(
        '-i', '--insert-statement'
        , action='append'
        , default=None
        )
    parser.add_argument(
        '-D', '--database-file'
        , default=None
        )
    parser.add_argument(
        '--batch'
        , default=None
        , type=int
        )
    parser.add_argument(
        '-t', '--total'
        , default=float('inf')
        , type=int
        )
    parser.add_argument(
        '-X', '--wipe-existing'
        , action='store_true'
        )
    parser.add_argument(
        '-v', '--verbose'
        , action='store_true'
        )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        '-e', '--exporter'
        , default=None
        )
    grp.add_argument(
        '-b', '--bind'
        , default=None
        , type=parse_bind
        )
    return parser.parse_args()

def parse_bind(inpt):
    """
    Custom parser for the --bind parameter.
    Currently supports ipv[4,6] with the ip:// scheme as well as UNIX domain
    sockets with the unix:// scheme. Defaults to ip:// .
    """
    if inpt is None:
        return None
    res = urlparse(inpt)
    if not res.scheme:
        res = urlparse('ip://' + inpt)
    if res.scheme == 'ip':
        hostname = res.hostname
        version = ip_address(hostname).version if hostname else 4
        if (not hostname) or hostname == 'localhost':
            hostname = '127.0.0.1' if version == 4 else '::1'
        if res.port is None:
            raise ValueError('No port for ip socket!', inpt)
        family = AF_INET if version == 4 else AF_INET6
        return (family, (hostname, res.port))
    if res.scheme == 'unix':
        if res.hostname == '' and res.path == '':
            raise ValueError('No socket path!', inpt)
        return (AF_UNIX, res.hostname + res.path)
    raise ValueError('Unsupported scheme', inpt)

if __name__ == "__main__":
    main()

