import { Button, Divider, Input, Select, Space } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useFormContext, useWatch } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { selectTagRender } from '@/components/form';
import { FormField } from '@/components/form/rhf';
import { createDefaultAnytlsClient } from '@/lib/xray/inbound-defaults';

const DEFAULT_PADDING_OPTIONS = [
  'stop=8',
  '0=30-30',
  '1=100-400',
  '2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000',
].map((v) => ({ label: v, value: v }));

export default function AnytlsFields() {
  const { t } = useTranslation();
  const { control, setValue } = useFormContext();
  const clients = (useWatch({ control, name: 'settings.clients' }) ?? []) as unknown[];

  return (
    <>
      <FormField
        name={['settings', 'paddingScheme']}
        label={t('pages.inbounds.omni.paddingScheme')}
      >
        <Select
          mode="tags"
          tagRender={selectTagRender}
          tokenSeparators={['\n']}
          options={DEFAULT_PADDING_OPTIONS}
          placeholder="stop=8"
        />
      </FormField>

      <Divider titlePlacement="start">{t('pages.inbounds.omni.initialClient')}</Divider>
      {clients.length === 0 ? (
        <Button
          size="small"
          icon={<PlusOutlined aria-hidden />}
          onClick={() => setValue('settings.clients', [createDefaultAnytlsClient()])}
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
