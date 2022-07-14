import sqlite3
from file import File
from url import URL

class Data:
    def __init__(self):
        # the number of files touched in the session, includes files that have been searched before
        self.num_files = 0
        # the number of urls touched in the session, includes urls that have been searched before
        self.num_urls = 0
        # connection to the database
        self.conn = sqlite3.connect('proj_data.db', check_same_thread = False)
        # cursor for the database
        self.c = self.conn.cursor()

        # Create both tables only once
        self.c.execute("""CREATE TABLE IF NOT EXISTS files (
                                        md5 text,
                                        sha256 text,
                                        sha1 text,
                                        ssdeep text,
                                        malicious integer,
                                        undetected integer,
                                        is_bad integer,
                                        size integer,
                                        engines text,
                                        results text
                                        )""")

        self.c.execute("""CREATE TABLE IF NOT EXISTS urls (
                                        user_entry text,
                                        domain_name text,
                                        comodo text,
                                        created_date text,
                                        registrar text,
                                        majestic integer,
                                        statvo integer,
                                        forcepoint text,
                                        undetected integer,
                                        malicious integer,
                                        engines text,
                                        results text
                                        )""")

    # Given a file object, store all the information in the database
    def store_file(self, the_file):
        print("\nStoring file in database\n")
        # use context manager to automatically commit changes to the database
        with self.conn:
            self.c.execute("""INSERT INTO files VALUES (:md5, :sha256, :sha1, :ssdeep, :malicious, :undetected,
                                                        :is_bad, :size, :engines, :results)""",
                                                        {'md5':the_file.md5_hash, 'sha256':the_file.sha256_hash,
                                                         'sha1':the_file.sha1_hash, 'ssdeep':the_file.ssdeep_hash,
                                                         'malicious':the_file.total_malicious,
                                                         'undetected':the_file.total_undetected,
                                                         'is_bad':the_file.is_malicious, 'size':the_file.size,
                                                         'engines':the_file.engines, 'results':the_file.engine_results})
        self.num_files += 1

    # Given a hash name, search each of the possible hash values for a single file and return a file object containing
    # the relevant information. If no file matches, return None
    def search_file(self, hash_name):
        print("\nSearching for Hash")
        self.c.execute("SELECT * FROM files WHERE md5=:hash OR sha256=:hash OR sha1=:hash OR ssdeep=:hash",
                       {'hash':hash_name})
        record = self.c.fetchone()
        if record is None:
            # do not increase num_files because no file is touched if it isn't found
            # if not found, the total will be incremented when the file is stored
            return None
        else:
            print("Found Hash\n")
            # extract info from the tuple and store in file object
            md5, sha256, sha1, ssdeep, mal, und, is_mal, size, engines, results = record
            the_file = File(md5_hash=md5, sha256_hash=sha256, sha1_hash=sha1, ssdeep_hash=ssdeep,
                            total_malicious=mal, total_undetected=und, is_malicious=is_mal, size=size,
                            engines=engines, results=results)
            self.num_files += 1
            return the_file

    # prints all rows in file table, used for debugging
    def print_all_files(self):
        self.c.execute("SELECT * FROM files")
        data = self.c.fetchall()
        for x in data:
            print(x)

    # Given a URL object, store all information in the database
    def store_url(self, the_url):
        print("\nStoring URL in database\n")
        with self.conn:
            self.c.execute("""INSERT INTO urls VALUES (:user_entry, :domain_name, :comodo, :created_date, :registrar, :majestic,
                                                        :statvo, :forcepoint, :undetected, :malicious, :engines,
                                                        :results)""",
                                                        {'user_entry':the_url.user_entry,
                                                         'domain_name':the_url.domain_name,
                                                         'comodo':the_url.comodo_valkyrie_verdict,
                                                         'created_date':the_url.created_date,
                                                         'registrar':the_url.registrar, 'majestic':the_url.rank_majestic,
                                                         'statvo':the_url.rank_statvo,
                                                         'forcepoint':the_url.forcepoint_threatseaker,
                                                         'undetected':the_url.total_undetected,
                                                         'malicious':the_url.total_malicious, 'engines':the_url.engines,
                                                         'results':the_url.engine_results})
            self.num_urls += 1

    # Given a domain name, search for a url and return information in the form of a URL object. If no url is found,
    # return None
    def search_url(self, user_entry):

        # # check to see if string passes has "www." or ".com"
        # # if not, return none as it could be an invalid domain
        # if ("www." not in user_entry) and (".com" not in user_entry):
        #     return None
        print("\nSearching for URL")
        self.c.execute("SELECT * FROM urls")
        record = self.c.fetchall()
        for x in record:
            ue, dn, cv, cd, rg, rm, rs, fp, tu, tm, eg, er = x
            # check if passed name is in stored names or if stored name is in passed name
            # this is to make sure google.com and https://www.google.com will find the stored google.com for example
            # print("USER_ENTRY:", user_entry)
            # print("ue:", ue)
            # print("Does", user_entry, "=", ue, "?", (user_entry == ue))
            
            if (user_entry == ue) or (ue == user_entry):
                print("Found URL\n")
                the_url = URL(ue, dn, cv, cd, rg, rm, rs, fp, tu, tm, eg, er)
                self.num_urls += 1
                return the_url
        # if none of the stored urls contain substring domain, the desired url is not stored so return None
        return None

    # prints all rows in url table, used for debugging
    def print_all_urls(self):
        self.c.execute("SELECT * FROM urls")
        data = self.c.fetchall()
        for x in data:
            print(x)
