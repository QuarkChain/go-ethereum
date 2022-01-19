
set -v
(cd cmd/geth && go build && mv geth ../../geth) && rm -rf ../datadir && ./geth import ../eth_data --datadir ../datadir --syncmode=full
