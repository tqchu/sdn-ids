sudo ip addr del 198.51.100.1/24 dev br0
sudo ip addr del 10.50.50.1/24   dev br0

sudo ip addr add 198.51.100.1/24 dev br0
sudo ip addr add 10.50.50.1/24   dev br0


ryu-manager    --verbose    --config-file l3.yaml controller.traffic_logger ryu.app.rest_router

curl -X POST -d '{"address":"198.51.100.1/24","mac":"00:00:00:aa:bb:01","port":1}'      http://localhost:8080/router/0000005056c00002
curl -X POST -d '{"address":"10.50.50.1/24","mac":"00:00:00:aa:bb:02","port":1}'      http://localhost:8080/router/0000005056c00002