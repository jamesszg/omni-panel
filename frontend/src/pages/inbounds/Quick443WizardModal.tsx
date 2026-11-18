import { useEffect, useId, useState } from 'react';
import {
  Alert,
  Button,
  Checkbox,
  Divider,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import { CopyOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { ClipboardManager, HttpUtil } from '@/utils';

interface GatewayTemplateSpec {
  id: string;
  name: string;
  description: string;
  core: string;
  protocol: string;
  transport: string;
  security: string;
  gatewayMode: string;
  recommendedAlpn?: string[];
  defaultPort: number;
  oneClickPreset: boolean;
  restrictions?: string[];
}

interface ClientShareBundle {
  email: string;
  protocol: string;
  core: string;
  uri: string;
  singboxOutboundJson?: string;
  warnings?: string[];
}

interface BootstrapCreatedInbound {
  id: number;
  tag: string;
  remark: string;
  core: string;
  protocol: string;
  port: number;
  publicPort: number;
  gatewayMode: string;
  templateId: string;
  bundles?: ClientShareBundle[];
}

interface BootstrapResult {
  domain: string;
  publicPort: number;
  subId: string;
  subUrl: string;
  inbounds?: BootstrapCreatedInbound[];
  warnings?: string[];
}

interface GatewayStatusView {
  domain?: string;
  publicPort?: number;
  acmeMode?: string;
  acmeEmail?: string;
  speedtestEnable?: boolean;
}

export interface Quick443WizardModalProps {
  open: boolean;
  onClose: () => void;
  onCompleted: () => void;
}

export default function Quick443WizardModal({
  open,
  onClose,
  onCompleted,
}: Quick443WizardModalProps) {
  const { t } = useTranslation();
  const uid = useId();
  const [messageApi, messageContextHolder] = message.useMessage();

  const [templates, setTemplates] = useState<GatewayTemplateSpec[]>([]);
  const [domain, setDomain] = useState('');
  const [publicPort, setPublicPort] = useState(443);
  const [presetIds, setPresetIds] = useState<string[]>([]);
  const [realityDest, setRealityDest] = useState('www.microsoft.com:443');
  const [realitySni, setRealitySni] = useState('www.microsoft.com');
  const [clientEmail, setClientEmail] = useState('');
  const [acmeMode, setAcmeMode] = useState('tls-alpn-01');
  const [acmeEmail, setAcmeEmail] = useState('');
  const [acmeCfApiToken, setAcmeCfApiToken] = useState('');
  const [speedtestEnable, setSpeedtestEnable] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<BootstrapResult | null>(null);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    (async () => {
      try {
        const [tplMsg, statusMsg] = await Promise.all([
          HttpUtil.get('/panel/api/gateway/templates', undefined, { silent: true }),
          HttpUtil.get('/panel/api/gateway/status', undefined, { silent: true }),
        ]);
        if (cancelled) return;
        if (tplMsg?.success && Array.isArray(tplMsg.obj)) {
          const list = tplMsg.obj as GatewayTemplateSpec[];
          setTemplates(list);
          setPresetIds((prev) => {
            if (prev.length > 0) return prev;
            const defaults = list.filter((x) => x.oneClickPreset).map((x) => x.id);
            return defaults.length > 0 ? defaults : list.slice(0, 1).map((x) => x.id);
          });
        }
        if (statusMsg?.success && statusMsg.obj && typeof statusMsg.obj === 'object') {
          const st = statusMsg.obj as GatewayStatusView;
          if (st.domain) setDomain((prev) => prev || st.domain || '');
          if (st.publicPort && st.publicPort > 0) setPublicPort(st.publicPort);
          if (st.acmeMode) setAcmeMode(st.acmeMode);
          if (st.acmeEmail) setAcmeEmail((prev) => prev || st.acmeEmail || '');
          if (typeof st.speedtestEnable === 'boolean') setSpeedtestEnable(st.speedtestEnable);
        }
      } catch {
        /* ignore when gateway routes unavailable */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open]);

  const copyValue = async (text: string) => {
    const ok = await ClipboardManager.copyText(text);
    if (ok) {
      messageApi.success(t('copied'));
    }
  };

  const handleBootstrap = async () => {
    if (!domain.trim()) {
      messageApi.warning(t('pages.inbounds.omni.domainRequired'));
      return;
    }
    setSubmitting(true);
    try {
      const msg = await HttpUtil.post('/panel/api/gateway/bootstrap', {
        domain: domain.trim(),
        publicPort: publicPort || 443,
        presetIds,
        realityDest: realityDest.trim() || 'www.microsoft.com:443',
        realitySni: realitySni.trim() || 'www.microsoft.com',
        clientEmail: clientEmail.trim(),
        acmeMode,
        acmeEmail: acmeEmail.trim(),
        acmeCfApiToken: acmeCfApiToken.trim(),
        speedtestEnable,
      });
      if (msg?.success && msg.obj) {
        setResult(msg.obj as BootstrapResult);
        messageApi.success(t('pages.inbounds.omni.bootstrapSuccess'));
        onCompleted();
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleClose = () => {
    setResult(null);
    onClose();
  };

  return (
    <>
      {messageContextHolder}
      <Modal
        open={open}
        width={760}
        onCancel={handleClose}
        destroyOnHidden
        title={
          <Space>
            <ThunderboltOutlined aria-hidden />
            <span>{t('pages.inbounds.omni.quick443Title')}</span>
          </Space>
        }
        footer={
          result ? (
            <Button type="primary" onClick={handleClose}>
              {t('close')}
            </Button>
          ) : (
            <Space>
              <Button onClick={handleClose}>{t('cancel')}</Button>
              <Button type="primary" loading={submitting} onClick={handleBootstrap}>
                {t('pages.inbounds.omni.bootstrapAction')}
              </Button>
            </Space>
          )
        }
      >
        {!result ? (
          <Form layout="vertical">
            <Form.Item
              htmlFor={`${uid}-domain`}
              label={t('pages.inbounds.omni.gatewayDomain')}
              required
            >
              <Input
                id={`${uid}-domain`}
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="proxy.example.com"
              />
            </Form.Item>
            <Space style={{ display: 'flex' }} size="middle" wrap>
              <Form.Item htmlFor={`${uid}-port`} label={t('pages.inbounds.omni.publicPort')}>
                <InputNumber
                  id={`${uid}-port`}
                  aria-label={t('pages.inbounds.omni.publicPort')}
                  min={1}
                  max={65535}
                  value={publicPort}
                  onChange={(v) => setPublicPort(v ?? 443)}
                />
              </Form.Item>
              <Form.Item htmlFor={`${uid}-acme`} label={t('pages.inbounds.omni.acmeMode')}>
                <Select
                  id={`${uid}-acme`}
                  style={{ width: 180 }}
                  value={acmeMode}
                  onChange={setAcmeMode}
                  options={[
                    { value: 'tls-alpn-01', label: 'TLS-ALPN-01 (Auto)' },
                    { value: 'dns-01-cf', label: 'Cloudflare DNS-01' },
                    { value: 'self-signed', label: 'Self-signed fallback' },
                  ]}
                />
              </Form.Item>
              <Form.Item
                htmlFor={`${uid}-speedtest`}
                label={t('pages.inbounds.omni.speedtestFallback')}
              >
                <Switch
                  id={`${uid}-speedtest`}
                  checked={speedtestEnable}
                  onChange={setSpeedtestEnable}
                />
              </Form.Item>
            </Space>
            {acmeMode !== 'self-signed' && (
              <Form.Item htmlFor={`${uid}-acme-email`} label={t('pages.inbounds.omni.acmeEmail')}>
                <Input
                  id={`${uid}-acme-email`}
                  value={acmeEmail}
                  onChange={(e) => setAcmeEmail(e.target.value)}
                  placeholder="admin@example.com"
                />
              </Form.Item>
            )}
            {acmeMode === 'dns-01-cf' && (
              <Form.Item
                htmlFor={`${uid}-acme-token`}
                label={t('pages.inbounds.omni.acmeCfApiToken')}
              >
                <Input.Password
                  id={`${uid}-acme-token`}
                  value={acmeCfApiToken}
                  onChange={(e) => setAcmeCfApiToken(e.target.value)}
                />
              </Form.Item>
            )}
            <Space style={{ display: 'flex' }} size="middle" wrap>
              <Form.Item
                htmlFor={`${uid}-reality-dest`}
                label={t('pages.inbounds.omni.realityDest')}
              >
                <Input
                  id={`${uid}-reality-dest`}
                  value={realityDest}
                  onChange={(e) => setRealityDest(e.target.value)}
                  placeholder="www.microsoft.com:443"
                />
              </Form.Item>
              <Form.Item htmlFor={`${uid}-reality-sni`} label={t('pages.inbounds.omni.realitySni')}>
                <Input
                  id={`${uid}-reality-sni`}
                  value={realitySni}
                  onChange={(e) => setRealitySni(e.target.value)}
                  placeholder="www.microsoft.com"
                />
              </Form.Item>
              <Form.Item htmlFor={`${uid}-client-email`} label={t('pages.clients.email')}>
                <Input
                  id={`${uid}-client-email`}
                  value={clientEmail}
                  onChange={(e) => setClientEmail(e.target.value)}
                  placeholder="default@omni"
                />
              </Form.Item>
            </Space>

            <Divider titlePlacement="start">{t('pages.inbounds.omni.selectPresets')}</Divider>
            <Checkbox.Group
              style={{ width: '100%' }}
              value={presetIds}
              onChange={(vals) => setPresetIds(vals as string[])}
            >
              <Space orientation="vertical" style={{ width: '100%' }} size="small">
                {templates.map((tpl) => (
                  <div
                    key={tpl.id}
                    style={{
                      padding: '8px 12px',
                      border: '1px solid rgba(128,128,128,0.2)',
                      borderRadius: 6,
                    }}
                  >
                    <Checkbox value={tpl.id}>
                      <Space wrap>
                        <strong>{tpl.name}</strong>
                        <Tag color={tpl.core === 'singbox' ? 'cyan' : 'blue'}>{tpl.core}</Tag>
                        <Tag>{tpl.gatewayMode}</Tag>
                      </Space>
                    </Checkbox>
                    {tpl.restrictions && tpl.restrictions.length > 0 && (
                      <Typography.Paragraph
                        type="secondary"
                        style={{ margin: '4px 0 0 24px', fontSize: 12 }}
                      >
                        {tpl.restrictions.join(' ')}
                      </Typography.Paragraph>
                    )}
                  </div>
                ))}
              </Space>
            </Checkbox.Group>
          </Form>
        ) : (
          <Space orientation="vertical" style={{ width: '100%' }} size="middle">
            {result.warnings && result.warnings.length > 0 && (
              <Alert
                type="warning"
                showIcon
                title={t('pages.inbounds.omni.gatewayWarnings')}
                description={result.warnings.join(' | ')}
              />
            )}
            {result.subUrl && (
              <div>
                <Typography.Text strong>{t('subscription.title')}</Typography.Text>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 4 }}>
                  <code style={{ flex: 1, wordBreak: 'break-all' }}>{result.subUrl}</code>
                  <Tooltip title={t('copy')}>
                    <Button
                      size="small"
                      aria-label={t('copy')}
                      icon={<CopyOutlined aria-hidden />}
                      onClick={() => copyValue(result.subUrl)}
                    />
                  </Tooltip>
                </div>
              </div>
            )}
            {(result.inbounds ?? []).map((ib) => (
              <div
                key={ib.id}
                style={{
                  padding: '8px 12px',
                  border: '1px solid rgba(128,128,128,0.2)',
                  borderRadius: 6,
                }}
              >
                <Space wrap>
                  <strong>{ib.remark || ib.tag}</strong>
                  <Tag color={ib.core === 'singbox' ? 'cyan' : 'blue'}>{ib.core}</Tag>
                  <Tag>{ib.protocol}</Tag>
                  <Tag>{ib.gatewayMode}</Tag>
                </Space>
                {(ib.bundles ?? []).map((b, idx) => (
                  <div key={`${ib.id}-${idx}`} style={{ marginTop: 8 }}>
                    {b.uri && (
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <code style={{ flex: 1, wordBreak: 'break-all', fontSize: 12 }}>
                          {b.uri}
                        </code>
                        <Tooltip title={t('copy')}>
                          <Button
                            size="small"
                            aria-label={t('copy')}
                            icon={<CopyOutlined aria-hidden />}
                            onClick={() => copyValue(b.uri)}
                          />
                        </Tooltip>
                      </div>
                    )}
                    {b.singboxOutboundJson && (
                      <div style={{ marginTop: 6 }}>
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                          }}
                        >
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            sing-box outbound JSON
                          </Typography.Text>
                          <Button
                            size="small"
                            icon={<CopyOutlined aria-hidden />}
                            onClick={() => copyValue(b.singboxOutboundJson ?? '')}
                          >
                            {t('copy')}
                          </Button>
                        </div>
                        <pre
                          style={{
                            margin: '4px 0 0',
                            padding: 8,
                            fontSize: 11,
                            overflowX: 'auto',
                            background: 'rgba(128,128,128,0.08)',
                            borderRadius: 4,
                          }}
                        >
                          <code>{b.singboxOutboundJson}</code>
                        </pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ))}
          </Space>
        )}
      </Modal>
    </>
  );
}
