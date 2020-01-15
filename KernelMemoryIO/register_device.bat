
SET BUILDCONFIG=Debug
FOR /F %%I IN ("%0") DO SET CURRENTDIR=%%~dpI

sc create "KernelMemoryIO" binPath= "%CURRENTDIR%\..\x64\%BUILDCONFIG%\KernelMemoryIO.sys" type= kernel start= demand
net start KernelMemoryIO