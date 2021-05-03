### This docker container contains only static module
Feel free to download complete image or build your own

https://drive.google.com/file/d/1alPus8mG57bFmXpHmDaXoUg7fpEZswNT/view?usp=sharing - link for MalDet archive to build your own image (see Dockerfile)

https://drive.google.com/file/d/1X0ltNmZi5_-TslEH1zaBmN90nP09nxy9/view?usp=sharing - link for complete docker image (see docker_run.txt).

### Instructions to get started 

```
docker load -i maldet.tar
docker run -it -p 8003:8003 a203fa0e8a72
cd MalDet/maldet/MalDet/
python3 MalDet.py
```
