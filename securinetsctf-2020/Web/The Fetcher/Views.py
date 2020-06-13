from django.shortcuts import render
from .forms import InputForm
import subprocess
def curl(link):
    proc = subprocess.Popen(['curl', link, '--max-time', '3'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return {'stdout':stdout,'stderr':stderr}
def home(request):
    if request.method=="GET":
        form=InputForm()
        msg="I'm the fetcher :D My work is to fetch links"
        return render(request,"index.html",{'msg':msg,'form':form.as_p()})
    elif request.method=="POST":
        form=InputForm(request.POST)
        if form.is_valid():
            try:
                link=form.cleaned_data["Input"]
                res=curl(link)
                msg="The result of the fetched url"
                return render(request,"index.html",{'msg':msg,'result':res['stdout'].decode(),'form':form.as_p()})
            except:
                msg="Sorry an unknown error has occured"
                return render(request,"index.html",{'msg':msg,'form':form.as_p()})

