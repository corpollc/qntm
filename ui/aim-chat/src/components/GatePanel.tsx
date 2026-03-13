import type { GateRecipe } from '../types'

export interface GatePanelProps {
  gateStatus: { promoted: boolean; orgId: string; threshold: number; signerCount: number }
  gateRecipes: GateRecipe[]
  selectedRecipe: string
  activeRecipe: GateRecipe | null
  gateServerUrl: string
  setGateServerUrl: (value: string) => void
  gateArgs: Record<string, string>
  gateOrgId: string
  gatePromoteThreshold: number
  setGatePromoteThreshold: (value: number) => void
  resolvedGateUrl: string
  secretService: string
  setSecretService: (value: string) => void
  secretValue: string
  setSecretValue: (value: string) => void
  secretHeaderName: string
  setSecretHeaderName: (value: string) => void
  secretHeaderTemplate: string
  setSecretHeaderTemplate: (value: string) => void
  isWorking: boolean
  onRecipeChange: (recipeName: string) => void
  onGateArgChange: (key: string, value: string) => void
  onGateRun: () => void
  onGatePromote: () => void
  onGateSecret: () => void
}

export function GatePanel({
  gateStatus,
  gateRecipes,
  selectedRecipe,
  activeRecipe,
  gateServerUrl,
  setGateServerUrl,
  gateArgs,
  gatePromoteThreshold,
  setGatePromoteThreshold,
  resolvedGateUrl,
  secretService,
  setSecretService,
  secretValue,
  setSecretValue,
  secretHeaderName,
  setSecretHeaderName,
  secretHeaderTemplate,
  setSecretHeaderTemplate,
  isWorking,
  onRecipeChange,
  onGateArgChange,
  onGateRun,
  onGatePromote,
  onGateSecret,
}: GatePanelProps) {
  return (
    <aside className="gate-panel">
      {/* Gate status banner */}
      <section className="panel gate-status-panel">
        {gateStatus.promoted ? (
          <div className="gate-status-info">
            <div className="gate-status-badge promoted">API Gateway Active</div>
            <div className="meta">
              <div><strong>Required approvals:</strong> {gateStatus.threshold} of {gateStatus.signerCount} signers</div>
              {gateStatus.orgId && <div><strong>Org:</strong> {gateStatus.orgId}</div>}
            </div>
          </div>
        ) : (
          <div className="gate-status-info">
            <div className="gate-status-badge inactive">API Gateway Inactive</div>
            <div className="meta">
              <div>Enable the API Gateway to make approved API calls as a group.</div>
            </div>
          </div>
        )}
      </section>

      {/* Promote section — shown when not promoted */}
      {!gateStatus.promoted && (
      <section className="panel">
        <h2>Enable API Gateway</h2>
        <div className="gate-hint">
          All conversation participants become signers.
          Set how many must approve each API call.
        </div>
        <label className="label" htmlFor="gate-promote-threshold">Required approvals</label>
        <input
          id="gate-promote-threshold"
          className="input"
          type="number"
          min={1}
          value={gatePromoteThreshold}
          onChange={(event) => setGatePromoteThreshold(Number(event.target.value) || 1)}
        />
        <button
          className="button full"
          type="button"
          disabled={isWorking}
          onClick={() => void onGatePromote()}
        >
          Enable API Gateway
        </button>
      </section>
      )}

      {/* API Request — only when promoted */}
      {gateStatus.promoted && (
      <section className="panel">
        <h2>API Request</h2>

        <label className="label" htmlFor="gate-recipe">API Template</label>
        <select
          id="gate-recipe"
          className="input"
          value={selectedRecipe}
          onChange={(event) => onRecipeChange(event.target.value)}
        >
          <option value="">Select a template...</option>
          {gateRecipes.map((recipe) => (
            <option key={recipe.name} value={recipe.name}>
              {recipe.name} — {recipe.verb} {recipe.endpoint}
            </option>
          ))}
        </select>

        <label className="label" htmlFor="gate-url">Gateway server</label>
        <input
          id="gate-url"
          className="input"
          placeholder="http://localhost:8080"
          value={gateServerUrl}
          onChange={(event) => setGateServerUrl(event.target.value)}
        />

        {activeRecipe && (
          <div className="gate-args">
            {(activeRecipe.path_params || []).length > 0 && (
              <>
                <div className="gate-args-heading">Path params</div>
                {activeRecipe.path_params!.map((param) => (
                  <div className="gate-arg-field" key={`path-${param.name}`}>
                    <label className="label" htmlFor={`gate-path-${param.name}`}>
                      {param.name}{param.required ? ' *' : ''}
                    </label>
                    <input
                      id={`gate-path-${param.name}`}
                      className="input"
                      placeholder={param.description || param.name}
                      value={gateArgs[param.name] || ''}
                      onChange={(e) => onGateArgChange(param.name, e.target.value)}
                    />
                  </div>
                ))}
              </>
            )}

            {(activeRecipe.query_params || []).length > 0 && (
              <>
                <div className="gate-args-heading">Query params</div>
                {activeRecipe.query_params!.map((param) => (
                  <div className="gate-arg-field" key={`query-${param.name}`}>
                    <label className="label" htmlFor={`gate-query-${param.name}`}>
                      {param.name}{param.required ? ' *' : ''}
                    </label>
                    <input
                      id={`gate-query-${param.name}`}
                      className="input"
                      placeholder={param.default || param.description || param.name}
                      value={gateArgs[param.name] || ''}
                      onChange={(e) => onGateArgChange(param.name, e.target.value)}
                    />
                  </div>
                ))}
              </>
            )}

            {(activeRecipe.body_schema as { properties?: Record<string, { description?: string; type?: string }> } | undefined)?.properties != null && (
              <>
                <div className="gate-args-heading">Body fields</div>
                {Object.entries((activeRecipe.body_schema as { properties: Record<string, { description?: string; type?: string }> }).properties).map(([key, prop]) => (
                  <div className="gate-arg-field" key={`body-${key}`}>
                    <label className="label" htmlFor={`gate-body-${key}`}>
                      {key}
                    </label>
                    <input
                      id={`gate-body-${key}`}
                      className="input"
                      placeholder={prop.description || prop.type || key}
                      value={gateArgs[key] || ''}
                      onChange={(e) => onGateArgChange(key, e.target.value)}
                    />
                  </div>
                ))}
              </>
            )}

            {!activeRecipe.body_schema && activeRecipe.body_example && (
              <>
                <div className="gate-args-heading">Request body</div>
                <textarea
                  className="token-box"
                  placeholder={JSON.stringify(activeRecipe.body_example, null, 2)}
                  value={gateArgs._body || ''}
                  onChange={(e) => onGateArgChange('_body', e.target.value)}
                />
              </>
            )}

            {resolvedGateUrl && (
              <div className="gate-url-preview">
                <span className={`gate-verb gate-verb-${activeRecipe.verb.toLowerCase()}`}>
                  {activeRecipe.verb}
                </span>{' '}
                <code>{resolvedGateUrl}</code>
              </div>
            )}
          </div>
        )}

        <button
          className="button full"
          type="button"
          disabled={isWorking || !selectedRecipe}
          onClick={() => void onGateRun()}
        >
          Submit API request
        </button>
      </section>
      )}

      {/* Secrets — only when promoted */}
      {gateStatus.promoted && (
      <section className="panel">
        <h2>API Keys</h2>
        <label className="label" htmlFor="secret-service">Service</label>
        <input
          id="secret-service"
          className="input"
          placeholder="e.g. stripe, github"
          value={secretService}
          onChange={(event) => setSecretService(event.target.value)}
        />
        <label className="label" htmlFor="secret-header-name">Header name</label>
        <input
          id="secret-header-name"
          className="input"
          placeholder="Authorization"
          value={secretHeaderName}
          onChange={(event) => setSecretHeaderName(event.target.value)}
        />
        <label className="label" htmlFor="secret-header-template">Header template</label>
        <input
          id="secret-header-template"
          className="input"
          placeholder="Bearer {value}"
          value={secretHeaderTemplate}
          onChange={(event) => setSecretHeaderTemplate(event.target.value)}
        />
        <label className="label" htmlFor="secret-value">Secret value</label>
        <input
          id="secret-value"
          className="input"
          type="password"
          placeholder="API key or token"
          value={secretValue}
          onChange={(event) => setSecretValue(event.target.value)}
        />
        <button
          className="button full"
          type="button"
          disabled={isWorking || !secretService.trim() || !secretValue}
          onClick={() => void onGateSecret()}
        >
          Add API key
        </button>
      </section>
      )}
    </aside>
  )
}
