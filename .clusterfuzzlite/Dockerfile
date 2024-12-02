FROM gcr.io/oss-fuzz-base/base-builder-python
RUN pip3 install hypothesis
RUN apt-get update && apt-get install -y poetry
COPY . $SRC/nvdinterface
WORKDIR $SRC/nvdinterface
RUN python -m poetry install
COPY ./.clusterfuzzlite/build.sh $SRC/