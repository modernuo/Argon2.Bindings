rm -rf ./tmp
docker build -t argon2-linux .
id=$(docker create argon2-linux)
docker cp $id:/runtimes ./tmp
docker rm -v $id
rsync -a --remove-source-files tmp/ runtimes/
rm -rf ./tmp