# Fastsub
A custom built DNS bruteforcer with multi-threading, and handling of bad resolvers.

Authored by Michael Skelton (@codingo_), Luke Stephens (@hakluke), and Sajeeb Lohani (@sml555_)

# Usage

## Threads
Always insure that the number of threads being used isn't more than 2x the number of cores in the destination machine, if so the application will still work but will have a performance hit, rather than benefit. You can check the number of cores with `nproc`.

```
➜  fastsub git:(master) ./fastsub -h 
[2019-09-14 19:31:20.467] [info] 

   ___         __           __
  / _/__ ____ / /____ __ __/ /
 / _/ _ `(_-</ __(_-</ // / _ \
/_/ \_,_/___/\__/___/\_,_/_.__/

Michael Skelton (@codingo_)
Luke Stephens (@hakluke)
Sajeeb Lohani (sml555_)



USAGE:

   ./fastsub  [-o <filename>] [-i <timeout in milliseconds>] [-c <integer>]
              [-x <integer>] -s <filename> -r <filename> [--] [--version]
              [-h] <Domain name>


Where:

   -o <filename>,  --output <filename>
     Output format{filename(json format), stdout}(default: stdout)

   -i <timeout in milliseconds>,  --timeout <timeout in milliseconds>
     Connection timeout for a request before it is disconnected and
     retried(default: 2,000ms)

   -c <integer>,  --threads <integer>
     Number of threads to use(default: 12)

   -x <integer>,  --retries <integer>
     Max retries(default: 10)

   -s <filename>,  --sub-domain <filename>
     (required)  A file containing a non-empty list of popular sub-domains

   -r <filename>,  --resolver <filename>
     (required)  A file containing the list of resolvers

   --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag.

   --version
     Displays version information and exits.

   -h,  --help
     Displays usage information and exits.

   <Domain name>
     (required)  domain name


   fastsub -> a fast subdomain finder

```
# Editing

## IDE
Built with a Visual Studio 2019 Solution file for an x64 Linux Environment.

## Compiling Instructions
Navigate to project directory and run:
```
cmake -G "Unix Makefiles"
make
```

## Docker
Build the container
```
docker build . -t fastsub
```

Run the container
```
docker run -t fastsub <args>
```
