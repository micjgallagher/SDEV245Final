SDEV245 Secret Finder


usage: main.py [-h] [-r RECURSE] path

positional arguments:
  path                  Path tool will search for sercrets

options:
  -h, --help            show this help message and exit
  -r RECURSE, --recurse RECURSE
                        Check subdirectories


Logic - 

Check if given path is valid, then will iterate over all files if path is a directory
Iterating through subdirectories can be done by using the -r flag
Searched files are split up by line and then pattern matched with regex pattern