FROM gcr.io/oss-fuzz-base/base-builder-python
RUN pip3 install hypothesis poetry
COPY . $SRC/nvdinterface
WORKDIR $SRC/nvdinterface
RUN python -m poetry install
COPY ./.clusterfuzzlite/build.sh $SRC/