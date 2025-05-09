#!/usr/bin/env bash

# Create build directory if it doesn't exist
mkdir -p build

platforms=("windows/amd64" "windows/386" "darwin/amd64")

for platform in "${platforms[@]}"
do
	platform_split=(${platform//\// })
	GOOS=${platform_split[0]}
	GOARCH=${platform_split[1]}
	output_name="jsweb-$GOOS-$GOARCH"
	if [ $GOOS = "windows" ]; then
		output_name+='.exe'
	fi	

	env GOOS=$GOOS GOARCH=$GOARCH go build -o build/$output_name
	if [ $? -ne 0 ]; then
   		echo 'An error has occurred! Aborting the script execution...'
		exit 1
	fi
done
