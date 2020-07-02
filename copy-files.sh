rm -rf ./tmp
id=$(docker create argon2-linux)
docker cp $id:/runtimes ./tmp
docker rm -v $id
rsync -a --remove-source-files tmp/ runtimes/