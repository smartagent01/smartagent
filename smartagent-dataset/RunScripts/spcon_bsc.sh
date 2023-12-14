# docker run --rm spcon-ethereum spcon --eth_address 0x2Ef27BF41236bD859a95209e17a43Fbd26851f92
# usage : ./spcon.sh {address} {date}
# this use case does not exist in spcon paper. low priority
docker run --rm spcon-bsc spcon --eth_address $1 --date $2