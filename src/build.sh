cd "$(dirname "$0")"

mkdir -p build
cd build

cmake ..

make -j

# # main 
# if [ -f ./main ]; then
#     echo -e "\n==== main execute ===="
#     ./main
# else
#     echo "no main file"
# fi
