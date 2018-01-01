ESP32 Alexa Client
=======================
This is a work in progress version of an Alexa client.

## Status

<ul>
    <li>Voice Recognition: done</li>
    <li>Wakeword Engine: TODO</li>
    <li>Audio Player: TODO</li>
    <li>Alerts: TODO</li>
</ul>

## Configuration
Before Configuring you need to execute this command from within the /ESP32-Alexa folder.

    git submodule init && git submodule update

Configure the project via menuconfig, there is an "Alexa config" menu.


## Alexa Authentication

You need to have an authentication token.

1. write down your ESP32's MAC address, its printed to the console on startup
2. go to https://alexa.boeckling.net/ and create a new authentication token
3. enter that token into the configuration option via menuconfig

## How To Use It

Once everything is setup, let it boot. A maniacal laugh will confirm that it is ready to receive orders. Press the GPIO0 button on your dev board to activate the microphone.

## Downloading Required Software

Get the SDK:

    git clone https://github.com/espressif/esp-idf.git
    cd esp-idf
    git submodule update --init

Set the IDF_PATH environment variable, and point it to this directory.

    export IDF_PATH=/path/to/esp-idf

Download the toolchain from: https://github.com/espressif/esp-idf#setting-up-esp-idf
You will need version 5.2.0.
Add /path/to/xtensa-esp32-elf/bin to your PATH:

    export PATH=/path/to/xtensa-esp32-elf/bin:$PATH

## Building

Execute 'make menuconfig' and configure your serial port, leave the rest at default settings and then execute 'make flash'.

## Connecting the I2S codec

If you don't know about the I2S standard, it is a special protocol for transferring digital audio data between chips, similar to I2C. There are many I2S chips you can choose from, the most important differences are:

1. Amplification: some chips only decode the audio to a low analog level, so you need a separate amp, but some also have a built-in amplifier. Most of these 2-in-1 chips are made for smartphones so their energy output is in the range of 2-4W, but some other ones made for domestic audio appliances can go a lot higher.
2. MCLK: this is a separate clock signal that sometimes needs to be a precise number in the MHz range that depends on the current sample rate, sometimes can be a single constant value ("asynchronous") independent of the current sample rate, and sometimes is not required at all. The ESP32 does not output a MCLK signal, so a chip that does not require MCLK is most convenient. If you already have an asynchronous one lying around (e.g. ES9023), you will need a quartz oscillator, usually in the range of 20-50MHz.

I tested several I2S codecs, and was happiest with the MAX98357A, because it does not require MCLCK and also amplifies the audio to speaker levels. It also seemed to be more immune to signal integrity issues, which do occur on breadboards. There is a convenient breakout board from Adafruit: https://www.adafruit.com/product/3006
However, any I2S codec should work.

Generic wiring:

```
ESP pin   - I2S signal
----------------------
GPIO25/DAC1   - LRCK
GPIO26/DAC2   - BCLK
GPIO22        - DATA
```

If you're using the MAX98357A, connect GND to ground and Vin to +5V (or +3.3V if +5V is unavailable). SD can remain unconnected, and GAIN too unless you want to make it louder or lower. I also recommend using a potentiometer for volume regulation.

## Connecting the I2S microphone

Connect the I2S microphone like this:
```
ESP pin   - I2S signal
----------------------
GPIO18   - LRCK
GPIO17   - BCLK
GPIO05   - DATA
```

These are known to work:
- https://www.tindie.com/products/onehorse/ics43434-i2s-digital-microphone/
- https://www.adafruit.com/product/3421

The ICS-43434 is higher quality than the SPH0645LM4H.

## Connecting the Neopixels

You need two Neopixels, simply chain them and connect data to GPIO_NUM_4.

## Demo

See this crappy video: https://www.youtube.com/watch?v=xRobZAVO_Io

## Purpose-Built Hardware

Microwavemont, the worlds fastest maker cavy, made a board specifically for this project. I can confirm it works out of the box! Get it here:
https://www.tindie.com/products/microwavemont/esp32-adb-edge/

## License
Mozilla Public License 2.0. Here is a summary of what this means: https://choosealicense.com/licenses/

