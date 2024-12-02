FROM gcr.io/oss-fuzz-base/base-builder-python
RUN pip3 install hypothesis poetry
COPY . $SRC/nvdinterface
WORKDIR $SRC/nvdinterface
COPY ./.clusterfuzzlite/build.sh $SRC/
RUN python -m poetry install