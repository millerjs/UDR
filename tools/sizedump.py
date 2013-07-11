from pylab import *
from numpy import *
from scipy import *
from scipy import optimize
from subprocess import call
import sys

def add_plot(path):

# Load data
    y = loadtxt(path,unpack=True, usecols=[0], skiprows=1)
    y = y*7.62939453e-6
    y2 = [y[i]-y[i-1] for i in range(1, len(y))]
    x = range(len(y2))

# Label PLot
    title = "File Transfer Rate:"
    xxis  = "Time (s)"
    yxis  = "Transfered file size (Gb)"
    ax.set_title(title)
    ax.set_xlabel(xxis)
    ax.set_ylabel(yxis)
    
    ax.plot(x,y2, alpha=.8, label=path)
    
# Create Legend
    ax.legend(loc='upper center', bbox_to_anchor=(0.85, .35),
              ncol=1, fancybox=True, shadow=True)    
    ax.yaxis.grid(color='gray', linestyle='dashed')
    ax.xaxis.grid(color='gray', linestyle='dashed')

# Create plot
plt = matplotlib.pyplot.figure()
ax = axes()
    
# Save  plot
plt.set_facecolor('white')

for f in sys.argv[1:]:
    print "Adding %s" % f
    add_plot(f)

plt.savefig('rates.png', bbox_inches=0)
# show()
 


