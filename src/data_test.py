from file import File
from url import URL
from data import Data

if __name__ == '__main__':
    # Testing for Data.py
    divide = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

    f1 = File("Tim", "Mark", "Clement", "Jenna")
    f2 = File("Biruk", "Scott", "Nick", "Kyle")

    u1 = URL(domain_name="Google")
    u2 = URL(domain_name="Amazon")

    print("\n", divide)
    # TEST 1
    the_db = Data()
    print("Printing both tables before inserting:\nPrinting contents of file table:")
    the_db.print_all_files()
    print("\nPrinting contents of urls table:")
    the_db.print_all_urls()
    print("\n", divide)

    # TEST 2
    print("\nInserting one thing into each table and printing the contents...")
    the_db.store_file(f1)
    the_db.store_url(u1)
    print("\nPrinting contents of file table:")
    the_db.print_all_files()
    print("\nPrinting contents of urls table:")
    the_db.print_all_urls()
    print("\n", divide)

    # TEST 3
    print("\nSearching for a file and url that are not in the tables...")
    fr = the_db.search_file("Biruk")
    ur = the_db.search_url("Amazon")
    if fr is None:
        print("File not found")
    else:
        print("Something went wrong")
    if ur is None:
        print("URL not found")
    else:
        print("Something went wrong")
    print("\n", divide)

    # TEST 4
    print("\nAdding another file and url to database...")
    the_db.store_file(f2)
    the_db.store_url(u2)
    print("\nPrinting contents of file table:")
    the_db.print_all_files()
    print("\nPrinting contents of urls table:")
    the_db.print_all_urls()
    print("\n", divide)

    # TEST 5
    print("\nSearching for a file and url that are in the tables...")
    fr = the_db.search_file("Biruk")
    ur = the_db.search_url("Amazon")
    if fr is not None:
        print("File found, md5 hash = ", fr.md5_hash)
    else:
        print("Something went wrong")
    if ur is not None:
        print("URL found, domain name = ", ur.domain_name)
    else:
        print("Something went wrong")
    print("\n", divide)

    # TEST 6
    print("\nSearching for a file by another hash other than md5...")
    fr = the_db.search_file("Scott")
    if fr is not None:
        print("File found, md5 hash =", fr.md5_hash)
    else:
        print("Something went wrong")
    print("\n", divide)
