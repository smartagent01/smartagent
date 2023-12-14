# docker run --rm spcon-ethereum spcon --eth_address 0x2Ef27BF41236bD859a95209e17a43Fbd26851f92
# usage : ./spcon.sh {address} {timeout} {date}
echo "Running SPCON... $1 $2 $3"

if [ -z "$3" ]; then
    timeout $2 docker run --rm spcon-ethereum timeout $2 spcon --eth_address $1
else
    timeout $2 docker run --rm spcon-ethereum timeout $2 spcon --eth_address $1 --date $3
fi
