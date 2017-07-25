# City Stop

This website allows users to add cities to a database and then share "stops" to visit in those cities. Users can "recommend" each other's stops which are then sorted by the number of recommendations they have received.

## Install

Can be installed from github repository.

`git clone
...`

Clone this file into the vagrant directory inside the fullstack-nanodegree-vm (see requirements).

## Usage

### Running the server

To start the server navigate to the city_stop directory and run the views.py module using python 3 eg:

`python3 views.py`

Visit localhost:5000 once the server is running to access the website.

Before running the program please check the requirements section and setup the database as detailed below.

### Setting up the database

To setup the database navigate to the city_stop directory and create the database by running the models module:

`python3 models.py`

## Requirements

To run the server a virtual machine is provided with all the necessary requirements.

This can be cloned from github using the following command:

`git clone https://github.com/udacity/fullstack-nanodegree-vm.git`

Running the virtual machine requires vagrant and Virtual Box.

Instructions for downloading Virtual Box can be found [here](https://www.virtualbox.org/).

And instructions for installing vagrant can be found [here](https://www.vagrantup.com/downloads.html).

Navigate to the vagrant file in the fullstack-nanodegree-vm and use the command `vagrant up` to start the machine. Use `vagrant halt` to stop it.
