NS=uca
kubectl -n $NS apply -f pg1.yaml
# kubectl config set-context --current --namespace=$NS
