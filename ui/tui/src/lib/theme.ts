/** TUI color theme — uses 256-color names supported by Ink/chalk */
export const theme = {
  // Brand
  brand: 'blueBright',        // primary brand color (headers, active items)
  brandDim: 'blue',           // secondary brand

  // Text
  text: 'white',              // primary text
  textDim: 'gray',            // secondary/muted text
  textInverse: 'black',       // text on colored backgrounds

  // Messages
  outgoing: 'greenBright',    // outgoing message sender
  incoming: 'cyanBright',     // incoming message sender (was magenta — hard to read)
  system: 'yellow',           // system messages

  // Status
  success: 'green',
  warning: 'yellow',
  error: 'red',
  info: 'blueBright',

  // UI chrome
  border: 'gray',
  borderActive: 'blueBright',
  borderComposer: 'greenBright',

  // Gate cards
  gateRequest: 'yellow',
  gateApproval: 'green',
  gateExecuted: 'blueBright',
  gateResult: 'green',
  gateError: 'red',
} as const
