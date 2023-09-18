#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/superstakeritemwidget.h>
#include <qt/platformstyle.h>
#include <qt/forms/ui_superstakeritemwidget.h>
#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>
#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <interfaces/node.h>
#include <chainparams.h>
#include <rpc/server.h>
#include <qt/guiutil.h>

#include <QFile>

class SuperStakerItemWidgetPriv
{
public:
    QString fee;
    QString staker;
    QString address;
    bool staking_on = false;
    int64_t balance = 0;
    int64_t stake = 0;
    int64_t weight = 0;
    int64_t delegationsWeight = 0;
};

#define SUPERSTAKER_ITEM_ICONSIZE 24
#define SUPERSTAKER_STAKER_SIZE 210
SuperStakerItemWidget::SuperStakerItemWidget(const PlatformStyle *platformStyle, QWidget *parent, ItemType type) :
    QWidget(parent),
    ui(new Ui::SuperStakerItemWidget),
    m_platfromStyle(platformStyle),
    m_type(type),
    m_position(-1),
    m_model(0),
    m_clientModel(0)

{
    ui->setupUi(this);
    ui->stackedWidget->setCurrentIndex(type);
    ui->buttonSplit->setIcon(platformStyle->MultiStatesIcon(":/icons/split", PlatformStyle::PushButtonIcon));
    ui->buttonConfig->setIcon(platformStyle->MultiStatesIcon(":/icons/configure", PlatformStyle::PushButtonIcon));
    ui->buttonRemove->setIcon(platformStyle->MultiStatesIcon(":/icons/remove_entry", PlatformStyle::PushButtonIcon));
    ui->buttonAdd->setIcon(platformStyle->MultiStatesIcon(":/icons/plus_full", PlatformStyle::PushButtonIcon));
    ui->buttonRestore->setIcon(platformStyle->MultiStatesIcon(":/icons/restore", PlatformStyle::PushButtonIcon));
    ui->superStakerLogo->setPixmap(platformStyle->MultiStatesIcon(m_type == New ? ":/icons/superstake" : ":/icons/staking_off").pixmap(SUPERSTAKER_ITEM_ICONSIZE, SUPERSTAKER_ITEM_ICONSIZE));

    ui->buttonDelegations->setToolTip(tr("Delegations for super staker"));
    ui->buttonSplit->setToolTip(tr("Split coins for super staker"));
    ui->buttonConfig->setToolTip(tr("Configure super staker"));
    ui->buttonRemove->setToolTip(tr("Remove super staker"));
    ui->buttonAdd->setToolTip(tr("Add super staker"));
    ui->buttonRestore->setToolTip(tr("Restore super stakers"));

    d = new SuperStakerItemWidgetPriv();
}

SuperStakerItemWidget::~SuperStakerItemWidget()
{
    delete ui;
}

void SuperStakerItemWidget::setData(const QString &fee, const QString &staker, const QString &address, const bool &staking_on, const int64_t &balance, const int64_t &stake, const int64_t &weight, const int64_t &delegationsWeight)
{
    // Set data
    d->fee = fee;
    d->staker = staker;
    d->address = address;
    d->staking_on = staking_on;
    d->balance = balance;
    d->stake = stake;
    d->weight = weight;
    d->delegationsWeight = delegationsWeight;

    // Update GUI
    if(d->fee != ui->labelFee->text())
        ui->labelFee->setText(d->fee);
    if(d->staker != ui->labelStaker->toolTip())
        updateLabelStaker();
    if(d->address != ui->labelAddress->text())
        ui->labelAddress->setText(d->address);
    updateLogo();
    updateBalance();
}

void SuperStakerItemWidget::setPosition(int position)
{
    m_position = position;
}

void SuperStakerItemWidget::on_buttonAdd_clicked()
{
    Q_EMIT clicked(m_position, Buttons::Add);
}

void SuperStakerItemWidget::on_buttonRemove_clicked()
{
    Q_EMIT clicked(m_position, Buttons::Remove);
}

void SuperStakerItemWidget::on_buttonConfig_clicked()
{
    Q_EMIT clicked(m_position, Buttons::Config);
}

void SuperStakerItemWidget::on_buttonDelegations_clicked()
{
    Q_EMIT clicked(m_position, Buttons::Delegations);
}

void SuperStakerItemWidget::on_buttonSplit_clicked()
{
    Q_EMIT clicked(m_position, Buttons::Split);
}

void SuperStakerItemWidget::on_buttonRestore_clicked()
{
    Q_EMIT clicked(m_position, Buttons::Restore);
}

int SuperStakerItemWidget::position() const
{
    return m_position;
}

void SuperStakerItemWidget::setModel(WalletModel *_model)
{
    m_model = _model;
    if(m_model && m_model->getOptionsModel())
    {
        connect(m_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SuperStakerItemWidget::updateDisplayUnit);
    }
    updateDisplayUnit();
}

void SuperStakerItemWidget::setClientModel(ClientModel *_clientModel)
{
    m_clientModel = _clientModel;
}

void SuperStakerItemWidget::updateDisplayUnit()
{
    updateBalance();
}

void SuperStakerItemWidget::updateBalance()
{
    int unit = BitcoinUnits::BTC;
    if(m_model && m_model->getOptionsModel())
        unit = m_model->getOptionsModel()->getDisplayUnit();
    ui->labelAssets->setText(BitcoinUnits::formatWithUnit(unit, d->balance, false, BitcoinUnits::SeparatorStyle::ALWAYS));
    ui->labelStake->setText(BitcoinUnits::formatWithUnit(unit, d->stake, false, BitcoinUnits::SeparatorStyle::ALWAYS));
}

void SuperStakerItemWidget::updateLabelStaker()
{
    QString text = d->staker;
    QFontMetrics fm = ui->labelStaker->fontMetrics();
    for(int i = d->staker.length(); i>3; i--)
    {
        text = GUIUtil::cutString(d->staker, i);
        if(GUIUtil::TextWidth(fm, text) < SUPERSTAKER_STAKER_SIZE)
            break;
    }
    ui->labelStaker->setText(text);
    ui->labelStaker->setToolTip(d->staker);
}
