import { Button, Divider, Input, InputNumber, Space } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useFormContext, useWatch } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { FormField } from '@/components/form/rhf';
import { createDefaultShadowtlsClient } from '@/lib/xray/inbound-defaults';

export default function ShadowtlsFields() {
  const { t } = useTranslation();
  const { control, setValue } = useFormContext();
  const clients = (useWatch({ control, name: 'settings.clients' }) ?? []) as unknown[];

  return (
    <>
      <FormField
        name={['settings', 'handshakeServer']}
        label={t('pages.inbounds.omni.handshakeServer')}
      >
        <Input placeholder="www.microsoft.com" />
      </FormField>
      <FormField
        name={['settings', 'handshakePort']}
        label={t('pages.inbounds.omni.handshakePort')}
      >
        <InputNumber min={1} max={65535} style={{ width: '100%' }} />
      </FormField>
      <FormField name={['settings', 'detour']} label={t('pages.inbounds.omni.shadowtlsDetour')}>
        <Input placeholder="" />
      </FormField>

      <Divider titlePlacement="start">{t('pages.inbounds.omni.initialClient')}</Divider>
      {clients.length === 0 ? (
        <Button
          size="small"
          icon={<PlusOutlined aria-hidden />}
          onClick={() => setValue('settings.clients', [createDefaultShadowtlsClient()])}
        >
          {t('pages.inbounds.omni.addInitialClient')}
        </Button>
      ) : (
        <>
          <FormField name={['settings', 'clients', 0, 'email']} label={t('pages.clients.email')}>
            <Input />
          </FormField>
          <FormField name={['settings', 'clients', 0, 'password']} label={t('password')}>
            <Input />
          </FormField>
          <Space>
            <Button
              size="small"
              danger
              icon={<DeleteOutlined aria-hidden />}
              onClick={() => setValue('settings.clients', [])}
            >
              {t('remove')}
            </Button>
          </Space>
        </>
      )}
    </>
  );
}
