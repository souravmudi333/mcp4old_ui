sudo az acr login --name fractalaicsdevacrdev
sudo docker build -t mcp_test .
sudo docker tag mcp_test fractalaicsdevacrdev.azurecr.io/mcp:test
sudo docker push fractalaicsdevacrdev.azurecr.io/mcp:test