import { useState } from 'react'

const STORAGE_KEY = 'gate-walkthrough-dismissed'

const steps = [
  {
    heading: 'What is the API Gateway?',
    description:
      'The API Gateway lets your group make approved API calls together. No single person can act alone \u2014 multiple approvals are required.',
  },
  {
    heading: 'Set Required Approvals',
    description:
      'Choose how many participants must approve each API call. For a 2-person conversation, set to 2 for unanimous approval.',
  },
  {
    heading: 'Enable the Gateway',
    description:
      "Click \u2018Enable API Gateway\u2019 to activate. All conversation participants become signers.",
  },
  {
    heading: 'Make API Calls',
    description:
      'After enabling, select an API Template, fill in parameters, and submit. Other participants will see the request and can approve it.',
  },
] as const

export function isDismissed(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === '1'
  } catch {
    return false
  }
}

function dismiss(): void {
  try {
    localStorage.setItem(STORAGE_KEY, '1')
  } catch {
    /* storage unavailable */
  }
}

export function GateWalkthrough({ onDone }: { onDone: () => void }) {
  const [current, setCurrent] = useState(0)
  const [dontShow, setDontShow] = useState(false)

  const step = steps[current]

  function finish() {
    if (dontShow) dismiss()
    onDone()
  }

  return (
    <div className="gate-walkthrough" role="region" aria-label="API Gateway walkthrough">
      <div className="gate-walkthrough-step">
        <div className="gate-walkthrough-indicator">
          {steps.map((_, i) => (
            <span
              key={i}
              className={`gate-walkthrough-dot${i === current ? ' active' : ''}${i < current ? ' done' : ''}`}
              aria-label={`Step ${i + 1} of ${steps.length}`}
            />
          ))}
        </div>

        <div className="gate-walkthrough-number">Step {current + 1} of {steps.length}</div>
        <h3 className="gate-walkthrough-heading">{step.heading}</h3>
        <p className="gate-walkthrough-desc">{step.description}</p>

        <div className="gate-walkthrough-nav">
          {current > 0 && (
            <button
              className="button gate-walkthrough-btn"
              type="button"
              onClick={() => setCurrent((c) => c - 1)}
            >
              Back
            </button>
          )}

          {current < steps.length - 1 ? (
            <button
              className="button gate-walkthrough-btn gate-walkthrough-btn-next"
              type="button"
              onClick={() => setCurrent((c) => c + 1)}
            >
              Next
            </button>
          ) : (
            <button
              className="button gate-walkthrough-btn gate-walkthrough-btn-next"
              type="button"
              onClick={finish}
            >
              Done
            </button>
          )}
        </div>

        <label className="gate-walkthrough-dismiss">
          <input
            type="checkbox"
            checked={dontShow}
            onChange={(e) => setDontShow(e.target.checked)}
          />
          Don&apos;t show again
        </label>
      </div>
    </div>
  )
}
