import { api } from '../api/client'
import { CampaignGraphView } from '../components/CampaignGraphView'
import { Card, ErrorState, Skeleton } from '../components/ui'
import { useResource } from '../lib/useResource'

export default function GraphPage() {
  const { data, error, reload } = useResource('graph', (signal) => api.graph(undefined, signal))
  const cases = data?.nodes.filter((node) => node.kind === 'case').length ?? 0

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Campaigns</h1>
          <p className="subtitle">
            Cases linked by shared infrastructure: origin IP, sender, domains, Reply-To, DKIM signer, link domains and
            attachments.
          </p>
        </div>
      </header>
      <Card
        title="Correlation graph"
        hint={data ? `${cases} linked cases · ${data.nodes.length - cases} shared indicators` : undefined}
      >
        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : data ? (
          <CampaignGraphView graph={data} height={620} />
        ) : (
          <Skeleton height={620} />
        )}
      </Card>
    </div>
  )
}
