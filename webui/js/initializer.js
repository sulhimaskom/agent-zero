

import * as device from './device.min.js';

export async function initialize(){
  // set device class to body tag
  setDeviceClass();
}

function setDeviceClass(){
  device.determineInputType().then((type) => {
    // Remove any class starting with 'device-' from <body>
    const body = document.body;
    body.classList.forEach(cls => {
      if (cls.startsWith('device-')) {
        body.classList.remove(cls);
      }
    });
    // Add the new device class
    body.classList.add(`device-${type}`);
  }).catch((error) => {
    // Silently handle device detection errors - fallback to pointer device
    document.body.classList.add('device-pointer');
  });
}
