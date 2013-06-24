from pylab import *
from numpy import *
from scipy import *
from scipy import optimize
from subprocess import call


# ------------------------------------------------------------------------
#                              Definitions
# ------------------------------------------------------------------------



bbox_props = dict(boxstyle="round4,pad=0.8", fc="cyan", ec="k", lw=2)

def scient(value):
    power = int(round(log10(abs(value))))
    if abs(power) >1:
        m = value/(10**(power-1))
        printer = "%.2f" % m
        printer = printer + "\\times10^{%d}" % (power-1)
    else:
        m = value
        printer = "%.2f" % m
    return str(printer)

def out(path, value):
    f = open(path, 'w')
    f.write(scient(value))

def stddev(f,p,x,y):
    Sum = sum( (f(p,x) - y)**2 )
    return sqrt(Sum/len(x))

def chisqr(f,p,x,y,df):
    e = stddev(f,p,x,y)
    return sum((y - f(p,x))**2/e**2)/(len(x) - df)
    
# ------------------------------------------------------------------------
#                             Curve fitting
# ------------------------------------------------------------------------
def fit(f,p,x,y):
    fitfunc = f
    errfunc = lambda p, x, y: fitfunc(p, x) - y
    p1, success = optimize.leastsq(errfunc, p, args=(x,y))
    return p1
    
# ------------------------------------------------------------------------
#                                 Plot
# ------------------------------------------------------------------------

# Load data
path = "./checkpoints"
y = loadtxt(path,unpack=True, usecols=[0], skiprows=1)

y = y*7.62939453e-6
y2 = []
for i in range(2,len(y)):
    y2.append(y[i]-y[i-1])


x = array(range(len(y)))
x2 = array(range(len(y2)))

# Create plot
plt = matplotlib.pyplot.figure()
ax = axes()

# Resize plot
# xlim(min(x), max(x))
# ylim(min(y), max(y)*1.1)

# Label PLot
title = "File Transfer Rate: SCP"
xaxis = "Time (s)"
yaxis = "Transfered file size (Gb)"
ax.set_title(title)
ax.set_xlabel(xaxis)
ax.set_ylabel(yaxis)

label1="File size"
label2="Transfer rate"

# Plot errobars
# ax.errorbar(x,y,xerr=xe,yerr=ye, fmt='c', alpha=.3, label=label1)
# ax.plot(x,y, 'k-.', alpha=.3, label=label1)
ax.plot(x2,y2, 'k', alpha=.3, label=label2)

# Create fit function for exponential data
f = lambda p, x: p[0]+ p[1]*exp(-x/p[2])
p = fit(f, [.1, 250, 1], x, y)

# Annotate curve
# chsqr = chisqr(f,p,x,y,3)
# dtau = stddev(f,p,x,y)
# ax.annotate(''
#             , size = 15
#             , xy=(7,f(p,7)), xytext=(10,100),
#             bbox=bbox_props,
#             arrowprops=dict(arrowstyle="->",
#                             connectionstyle="arc3,rad=.1"))

# Create Legend
ax.legend(loc='upper center', bbox_to_anchor=(0.85, .95),
          ncol=1, fancybox=True, shadow=True)    
ax.yaxis.grid(color='gray', linestyle='dashed')
ax.xaxis.grid(color='gray', linestyle='dashed')

# Save  plot
plt.set_facecolor('white')
plt.savefig(path[:-8]+'.png', bbox_inches=0)
show()
 


