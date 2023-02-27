# import pandas as pd
# # import numpy as np


class Name:
    def __init__(self,name,lname):
        self.name=name
        self.lname=lname
        self.show()

    def show(self):
        return self.name,self.lname
    
obj=Name("pratap","singh")
obj.show()

